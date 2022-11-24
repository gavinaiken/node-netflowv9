var decNumRule = {
    1: "o['$name']=buf.readUInt8($pos);",
    2: "o['$name']=buf.readUInt16BE($pos);",
    3: "o['$name']=buf.readUInt8($pos)*65536+buf.readUInt16BE($pos+1);",
    4: "o['$name']=buf.readUInt32BE($pos);",
    5: "o['$name']=buf.readUInt8($pos)*4294967296+buf.readUInt32BE($pos+1);",
    6: "o['$name']=buf.readUInt16BE($pos)*4294967296+buf.readUInt32BE($pos+2);",
    8: "o['$name']=buf.readUInt32BE($pos)*4294967296+buf.readUInt32BE($pos+4);"
};

var decTimestamp = decNumRule;
var decTsMs = decTimestamp;
var decTsMcs = decTimestamp;
var decTsNs = decTimestamp;

var decIpv4Rule = {
    4: "o['$name']=(t=buf.readUInt32BE($pos),(parseInt(t/16777216)%256)+'.'+(parseInt(t/65536)%256)+'.'+(parseInt(t/256)%256)+'.'+(t%256));"
};

var decIpv6Rule = {
    16: "o['$name']=buf.toString('hex',$pos,$pos+$len);"
};

var decMacRule = {
    0: "o['$name']=buf.toString('hex',$pos,$pos+$len);"
};

var decStringRule = {
    0: 'o[\'$name\']=buf.toString(\'utf8\',$pos,$pos+$len).replace(/\\0/g,\'\');'
};

var decAsciiStringRule = {
    0: 'o[\'$name\']=buf.toString(\'ascii\',$pos,$pos+$len).replace(/\\0/g,\'\');'
};

module.exports = {
    decNumRule: decNumRule,
    decTimestamp: decTimestamp,
    decTsMs: decTsMs,
    decTsMcs: decTsMcs,
    decTsNs: decTsNs,
    decIpv4Rule: decIpv4Rule,
    decIpv6Rule: decIpv6Rule,
    decMacRule: decMacRule,
    decStringRule: decStringRule,
    decAsciiStringRule: decAsciiStringRule,
};
