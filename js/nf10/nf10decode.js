var debug = require('debug')('NetFlowV9');

const { decMacRule } = require('../nf9/fieldRules');

function nf10PktDecode(msg, rinfo) {
    var templates = this.nfInfoTemplates(rinfo);
    var nfTypes = this.nfTypes || {};
    var enterpriseTypes = this.enterpriseTypes || {};

    var out = { header: {
        version: msg.readUInt16BE(0),
        length: msg.readUInt16BE(2),
        exportTime: msg.readUInt32BE(4),
        sequence: msg.readUInt32BE(8),
        sourceId: msg.readUInt32BE(12) // spec calls this Observation Domain ID but using sourceId allows for simpler interoperability with v9
    }, flows: [] };

    debug(out.header);

    function appendTemplate(tId) {
        var id = rinfo.address + ':' + rinfo.port;
        out.templates = out.templates || {};
        out.templates[id] = out.templates[id] || {};
        out.templates[id][tId] = templates[tId];
    }

    function getType(enterpriseNumber, type, addIfNotFound) {
        if (addIfNotFound) {
            let nf;
            if (enterpriseNumber) {
                if (!enterpriseTypes[enterpriseNumber]) {
                    enterpriseTypes[enterpriseNumber] = {};
                }
                nf = enterpriseTypes[enterpriseNumber][type];
                if (!nf) {
                    debug('Unknown NF type %d for enterprise %d', type, enterpriseNumber);
                    nf = enterpriseTypes[enterpriseNumber][type] = {
                        name: `unknown_type_${enterpriseNumber}_${type}`,
                        compileRule: decMacRule
                    };
                }
            } else {
                nf = nfTypes[type];
                if (!nf) {
                    debug('Unknown NF type %d', type);
                    nf = nfTypes[type] = {
                        name: 'unknown_type_' + type,
                        compileRule: decMacRule
                    };
                }
            }
            return nf;
        }
        return enterpriseNumber && enterpriseTypes[enterpriseNumber] ? enterpriseTypes[enterpriseNumber][type] : nfTypes[type];
    }

    function compileStatement(enterpriseNumber, type, pos, len) {
        let nf = getType(enterpriseNumber, type, false);
        let cr = null;
        if (nf && nf.compileRule) {
            cr = nf.compileRule[len] || nf.compileRule[0];
            if (cr) {
                return cr.toString().replace(/(\$pos)/g, function (n) {
                    // offset handles the position increment for variable length fields
                    return 'offset+' + pos;
                }).replace(/(\$len)/g, function (n) {
                    return len;
                }).replace(/(\$name)/g, function (n) {
                    return nf.name;
                });
            }
        }
        debug('Unknown compile rule TYPE: %d POS: %d LEN: %d', type, pos, len);
        return "";
    }

    function compileTemplate(list) {
        var i, z, n;
        var f = "var o = Object.create(null); var t; var l; var offset = 0;\n";
        var listLen = list ? list.length : 0;
        for (i = 0, n = 0; i < listLen; i++, n += z.len) {
            z = list[i];
            getType(z.enterpriseNumber, z.type, true);
            f += compileStatement(z.enterpriseNumber, z.type, n, z.len) + ";\n";
        }
        f += "return { o, offset };\n";
        debug('The template will be compiled to %s', f);
        return new Function('buf', 'nfTypes', f);
    }

    function readTemplate(buffer) {
        // var fsId = buffer.readUInt16BE(0);
        let setLen = buffer.readUInt16BE(2);
        let buf = buffer.slice(4, setLen);

        // debug(`trying to compile template length ${len} (buf len ${buf.length})`, JSON.stringify({ rinfo, buffer: msg }));
        while (buf.length > 0) {
            let tId = buf.readUInt16BE(0);
            let cnt = buf.readUInt16BE(2);
            // debug('tId, cnt, buf length', tId, cnt, buf.length)
            let list = [];
            let len = 0, pos = 0;
            for (let i = 0; i < cnt; i++) {
                let fieldSpecifier = { enterpriseBit: 0, enterpriseNumber: undefined, type: buf.readUInt16BE(4 + 4 * pos), len: buf.readUInt16BE(6 + 4 * pos) };
                pos++;
                if (fieldSpecifier.type > 0x8000) {
                    fieldSpecifier.type = fieldSpecifier.type & 0x7fff;
                    fieldSpecifier.enterpriseBit = 1;
                    fieldSpecifier.enterpriseNumber = buf.readUInt32BE(4 + 4 * pos);
                    pos++;
                }
                // debug(fieldSpecifier);
                list.push(fieldSpecifier);
                // 65535 implies field is variable len, so incr template total len by just 1 byte
                // (for the initial variable len byte) and everything else will be handled by dynamic
                // offsets within the template
                len += fieldSpecifier.len === 65535 ? 1 : fieldSpecifier.len;
            }
            debug('compile template %s for %s:%d', tId, rinfo.address, rinfo.port);
            templates[tId] = { len: len, list: list, compiled: compileTemplate(list) };
            appendTemplate(tId);
            buf = buf.slice(4 + pos * 4);
        }
    }

    function decodeTemplate(fsId, buf) {
        if (typeof templates[fsId].compiled !== 'function') {
            templates[fsId].compiled = compileTemplate(templates[fsId].list);
        }
        var result = templates[fsId].compiled(buf, nfTypes);
        result.o.fsId = fsId;
        return result;
    }

    function compileScope(enterpriseNumber, type, pos, len) {
        let nf = getType(enterpriseNumber, type, true);

        var cr = null;
        if (nf.compileRule) {
            cr = nf.compileRule[len] || nf.compileRule[0];
            if (cr) {
                return cr.toString().replace(/(\$pos)/g, function (n) {
                    return pos;
                }).replace(/(\$len)/g, function (n) {
                    return len;
                }).replace(/(\$name)/g, function (n) {
                    return nf.name;
                });
            }
        }
        debug('Unknown compile scope rule TYPE: %d POS: %d LEN: %d', type, pos, len);
        return "";
    }

    function readOptions(buffer) {
        let setLen = buffer.readUInt16BE(2);
        let buf = buffer.slice(4, setLen);
        debug('readOptions: setLen:%d buf:%s for %s:%d', setLen, buf.toString('hex'), rinfo.address, rinfo.port);

        // Read the SCOPE
        // var buf = buff.slice(0, osLen);
        while (buf.length > 0) {
            let tId = buf.readUInt16BE(0);
            let count = buf.readUInt16BE(2);
            let scopeCount = buf.readUInt16BE(4);
            let fieldCount = count - scopeCount;

            let cr = "var o={ isOption: true }; var t;\n";
            let list = [];
            let len = 0, pos = 0;

            // scope fields come first
            for (let i = 0; i < scopeCount; i++) {
                let fieldSpecifier = { enterpriseBit: 0, enterpriseNumber: undefined, type: buf.readUInt16BE(6 + 4 * pos), len: buf.readUInt16BE(8 + 4 * pos) };
                pos++;
                if (fieldSpecifier.type > 0x8000) {
                    fieldSpecifier.type = fieldSpecifier.type & 0x7fff;
                    fieldSpecifier.enterpriseBit = 1;
                    fieldSpecifier.enterpriseNumber = buf.readUInt32BE(6 + 4 * pos);
                    pos++;
                }
                // debug(fieldSpecifier);
                list.push(fieldSpecifier);
                let nf = getType(fieldSpecifier.enterpriseNumber, fieldSpecifier.type, true);
                debug('    SCOPE type: %s %d (%s) len: %d, plen: %d', fieldSpecifier.enterpriseNumber, fieldSpecifier.type, nf ? nf.name : 'unknown', fieldSpecifier.len, len);
                if (fieldSpecifier.type > 0) { cr += compileScope(fieldSpecifier.enterpriseNumber, fieldSpecifier.type, len, fieldSpecifier.len); }
                len += fieldSpecifier.len;
            }

            // now read the options fields
            for (let i = 0; i < fieldCount; i++) {
                let fieldSpecifier = { enterpriseBit: 0, enterpriseNumber: undefined, type: buf.readUInt16BE(6 + 4 * pos), len: buf.readUInt16BE(8 + 4 * pos) };
                pos++;
                if (fieldSpecifier.type > 0x8000) {
                    fieldSpecifier.type = fieldSpecifier.type & 0x7fff;
                    fieldSpecifier.enterpriseBit = 1;
                    fieldSpecifier.enterpriseNumber = buf.readUInt32BE(6 + 4 * pos);
                    pos++;
                }
                // debug(fieldSpecifier);
                list.push(fieldSpecifier);
                let nf = getType(fieldSpecifier.enterpriseNumber, fieldSpecifier.type, false);
                debug('    FIELD type: %s %d (%s) len: %d, len: %d', fieldSpecifier.enterpriseNumber, fieldSpecifier.type, nf ? nf.name : 'unknown', fieldSpecifier.len, len);
                if (fieldSpecifier.type > 0) { cr += compileStatement(fieldSpecifier.enterpriseNumber, fieldSpecifier.type, len, fieldSpecifier.len); }
                len += fieldSpecifier.len;
            }

            cr += `// option ${tId}\n`;
            cr += "return o;";
            debug('option template compiled to %s', cr);
            templates[tId] = { len: len, compiled: new Function('buf', 'nfTypes', cr) };
            appendTemplate(tId);

            buf = buf.slice(6 + pos * 4);
        }
    }

    var buf = msg.slice(16);
    while (buf.length > 3) { // length > 3 allows us to skip padding
        var fsId = buf.readUInt16BE(0);
        var len = buf.readUInt16BE(2);
        // debug(`fsId len`, fsId, len);
        if (fsId === 2) {
            readTemplate(buf);
        } else if (fsId === 3) {
            readOptions(buf);
        } else if (fsId > -1 && fsId < 256) {
            debug('Unknown Flowset ID %d!', fsId);
        } else if (fsId > 255 && typeof templates[fsId] !== 'undefined') {
            var tbuf = buf.slice(4, len);
            while (tbuf.length >= templates[fsId].len) {
                let result = decodeTemplate(fsId, tbuf);
                out.flows.push(result.o);
                tbuf = tbuf.slice(templates[fsId].len + result.offset);
            }
        } else if (fsId > 255) {
            debug('Unknown template/option data with flowset id %d for %s:%d', fsId, rinfo.address, rinfo.port);
        }
        buf = buf.slice(len);
        if (len === 0) {
            break;
        }
    }

    return out;
}

module.exports = nf10PktDecode;
