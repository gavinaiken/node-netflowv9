var debug = require('debug')('NetFlowV9');

var decMacRule = {
    0: "o['$name']=buf.toString('hex',$pos,$pos+$len);"
};

function nf9PktDecode(msg,rinfo) {
    var templates = this.nfInfoTemplates(rinfo);
    var nfTypes = this.nfTypes || {};
    var nfScope = this.nfScope || {};
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

    function compileStatement(nf, pos, len) {
        var cr = null;
        if (nf && nf.compileRule) {
            cr = nf.compileRule[len] || nf.compileRule[0];
            if (cr) {
                return cr.toString().replace(/(\$pos)/g, function (n) {
                    return pos
                }).replace(/(\$len)/g, function (n) {
                    return len
                }).replace(/(\$name)/g, function (n) {
                    return nf.name
                });
            }
        }
        debug('Unknown compile rule TYPE: %d POS: %d LEN: %d',type,pos,len);
        return "";
    }

    function compileTemplate(list) {
        var i, z, nf, n;
        var f = "var o = Object.create(null); var t;\n";
        var listLen = list ? list.length : 0;
        for (i = 0, n = 0; i < listLen; i++, n += z.len) {
            z = list[i];
            nf = z.enterpriseBit === 1 ? enterpriseTypes[z.enterpriseNumber]?.[z.type] : nfTypes[z.type];
            if (!nf) {
                debug('Unknown NF type %d', z.type);
                nf = nfTypes[z.type] = {
                    name: 'unknown_type_'+ z.type,
                    compileRule: decMacRule
                };
            }
            f += compileStatement(nf, n, z.len) + ";\n";
        }
        f += "return o;\n";
        debug('The template will be compiled to %s',f);
        return new Function('buf', 'nfTypes', f);
    }

    function readTemplate(buffer) {
        // var fsId = buffer.readUInt16BE(0);
        let len = buffer.readUInt16BE(2);
        let buf = buffer.slice(4, len);

        // debug(`trying to compile template length ${len} (buf len ${buf.length})`, JSON.stringify({ rinfo, buffer: msg }));
        while (buf.length > 0) {
            let tId = buf.readUInt16BE(0);
            let cnt = buf.readUInt16BE(2);
            debug('tId, cnt, buf length', tId, cnt, buf.length)
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
                len += fieldSpecifier.len;
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
        var o = templates[fsId].compiled(buf, nfTypes);
        o.fsId = fsId;
        return o;
    }

    function compileScope(type,pos,len) {
        if (!nfScope[type]) {
            nfScope[type] = { name: 'unknown_scope_'+type, compileRule: decMacRule };
            debug('Unknown scope TYPE: %d POS: %d LEN: %d',type,pos,len);
        }

        var nf = nfScope[type];
        var cr = null;
        if (nf.compileRule) {
            cr = nf.compileRule[len] || nf.compileRule[0];
            if (cr) {
                return cr.toString().replace(/(\$pos)/g, function (n) {
                    return pos
                }).replace(/(\$len)/g, function (n) {
                    return len
                }).replace(/(\$name)/g, function (n) {
                    return nf.name
                });
            }
        }
        debug('Unknown compile scope rule TYPE: %d POS: %d LEN: %d',type,pos,len);
        return "";
    }

    // TODO - needs to be updated to IPFix
    function readOptions(buffer) {
        var len = buffer.readUInt16BE(2);
        var tId = buffer.readUInt16BE(4);
        var osLen = buffer.readUInt16BE(6);
        var oLen = buffer.readUInt16BE(8);
        var buff = buffer.slice(10,len);
        debug('readOptions: len:%d tId:%d osLen:%d oLen:%d for %s:%d',len,tId,osLen,oLen,buff,rinfo.address,rinfo.port);
        var plen = 0;
        var cr = "var o={ isOption: true }; var t;\n";
        var type; var tlen;

        // Read the SCOPE
        var buf = buff.slice(0,osLen);
        while (buf.length > 3) {
            type = buf.readUInt16BE(0);
            tlen = buf.readUInt16BE(2);
            debug('    SCOPE type: %d (%s) len: %d, plen: %d', type,nfTypes[type] ? nfTypes[type].name : 'unknown',tlen,plen);
            if (type>0) cr+=compileScope(type, plen, tlen);
            buf = buf.slice(4);
            plen += tlen;
        }

        // Read the Fields
        buf = buff.slice(osLen);
        while (buf.length > 3) {
            type = buf.readUInt16BE(0);
            tlen = buf.readUInt16BE(2);
            debug('    FIELD type: %d (%s) len: %d, plen: %d', type,nfTypes[type] ? nfTypes[type].name : 'unknown',tlen,plen);
            if (type>0) cr+=compileStatement(nfTypes[type], plen, tlen);
            buf = buf.slice(4);
            plen += tlen;
        }
        cr+="// option "+tId+"\n";
        cr+="return o;";
        debug('option template compiled to %s',cr);
        templates[tId] = { len: plen, compiled: new Function('buf','nfTypes',cr) };
        appendTemplate(tId);
    }

    var buf = msg.slice(16);
    while (buf.length > 3) { // length > 3 allows us to skip padding
        var fsId = buf.readUInt16BE(0);
        var len = buf.readUInt16BE(2);
        if (fsId == 2) readTemplate(buf);
        else if (fsId == 3) readOptions(buf);
        else if (fsId > -1 && fsId < 256) {
            debug('Unknown Flowset ID %d!', fsId);
        }
        else if (fsId > 255 && typeof templates[fsId] != 'undefined') {
            var tbuf = buf.slice(4, len);
            while (tbuf.length >= templates[fsId].len) {
                out.flows.push(decodeTemplate(fsId, tbuf));
                tbuf = tbuf.slice(templates[fsId].len);
            }
        } else if (fsId > 255) {
            debug('Unknown template/option data with flowset id %d for %s:%d',fsId,rinfo.address,rinfo.port);
        }
        buf = buf.slice(len);
        if (len == 0) {
            break;
        }
    }

    return out;
}

module.exports = nf9PktDecode;
