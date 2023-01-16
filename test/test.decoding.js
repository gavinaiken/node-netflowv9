const expect = require('chai').expect;

const NetFlowV9 = require('../netflowv9');

// v9
const VYOS_PACKET = '000900070002549b53b289a200000001000000000000005c0400001500150004001600040001000400020004003c0001000a0002000e0002003d00010003000400080004000c000400070002000b00020005000100060001000400010038000600500006003a000200c90004003000010000005c0401001500150004001600040001000400020004003c0001000a0002000e0002003d00010003000400080004000c000400070002000b00020005000100060001000400010051000600390006003b000200c90004003000010000005c0800001500150004001600040001000400020004003c0001000a0002000e0002003d000100030004001b0010001c00100005000100070002000b000200060001000400010038000600500006003a000200c90004003000010000005c0801001500150004001600040001000400020004003c0001000a0002000e0002003d000100030004001b0010001c00100005000100070002000b000200060001000400010051000600390006003b000200c90004003000010001001a10000004000c000100040030000100310001003200041000000e000000000102000001f4040000400000209e0000209e0000002800000001040003000000000000000a640054c0004c0264aa0050001006001b2fb9484980ee7395562800000000000301';

// v10 / IPFIX
const SONICWALL_TEMPLATE = '000a00585b6b5242000010bda07e8c0000020048010000100001000400020004000400010008000400070002000a0004000b0002000c0004000e0004000f0004001500040016000400e1000400e2000400e3000200e40002';
const SONICWALL_DATA = '000a011d5b6b86c50000acf0a07e8c000100010d0010d49a000002fa06acd9022501bb00000002a3290a0000ed000000010a00000100dedac800debb88acd90225c0a8a84101bbdd690000009d00000001114b4b4b4b003500000002222c0a0000ed000000010a00000100de715000de71504b4b4b4bc0a8a8410035398f0000024600000005114a7d8a7101bb00000002d3d10a0000ed000000010a00000100de715000de71504a7d8a71c0a8a84101bb9ca40000038300000004114a7d8a7101bb0000000268920a0000ed000000010a00000100de715000de71504a7d8a71c0a8a84101bba46b000001c6000000040623a8ede501bb000000023d1b0a0000ed000000010a00000100de753800023a5023a8ede5c0a8a84101bbeb10';

const CISCO_TEMPLATE = '000a0078637de5bb0006ec670000040000020068010a001400080004000c0004000a000400c300010004000100070002000b00020006000100880001b090000400000009b092000400000009b099000800000009005f0004000e000400300001b09100040000000900010008000200080098000800990008';
const CISCO_DATA = '000a0068637de5bb0006ec6700000400010a00588efa45ee0a0104ce0000000b201101bbd4370001000000000000000ab9e5ec70000521640d0002080000000a02000019030000000000000035000000000000000100000184a3c93e7700000184a3c93e77000000';

const YAF_TEMPLATE = '000a03605b6cb59300008a310000000000020228c013000600b80004800e000100001ad7800f000100001ad7c00e000100001ad7c00f000100001ad780b8000400007279c015001781f6000800001ad781f7000800001ad781f8000800001ad700df000481f4000400001ad781f5000400001ad781fe000400001ad781f9000200001ad781fa000200001ad781fc000200001ad781fb000100001ad700d20001c1f6000800001ad7c1f7000800001ad7c1f8000800001ad780df000400007279c1f4000400001ad7c1f5000400001ad7c1fe000400001ad7c1f9000200001ad7c1fa000200001ad7c1fc000200001ad700d20002b301000e0098000800990008005500040056000400080004000c000400070002000b00028028000200001ad70004000100880001003a0002000500010125ffffc01800028012ffff00001ad7c012ffff00001ad7b80000270098000800990008005500088055000800007279005600088056000800007279000100088001000800007279000200088002000800007279001b0010001c001000080004000c000400070002000b00028028000200001ad7c028000200001ad7000400010088000100d200028015000400001ad700b8000480b8000400007279800e000100001ad7800f000100001ad7c00e000100001ad7c00f000100001ad7003a0002803a000200007279000a0004000e000400050001800500010000727900460003004700030048000300d200050125ffffc003000300b80004800e000100001ad7800f000100001ad70003007cd000000e000200a00008002a0008005600080087000800a4000800a700088064000400001ad78065000400001ad78068000400001ad78069000400001ad700820004009000048066000400001ad78067000400001ad7d001000400028227000200001ad78228000200001ad78226000400001ad70124ffff000200acd00200020090000401420004c00400020038000600500006c005000b81f6000800001ad781f7000800001ad781f8000800001ad700df000481f4000400001ad781f5000400001ad781fe000400001ad781f9000200001ad781fa000200001ad781fc000200001ad781fb000100001ad7c00900058121000800001ad78122000400001ad78123000200001ad78124000100001ad78125000100001ad7c00800018012ffff00001ad7';
const YAF_DATA = '000a05875b6b68f5000088b200000000b30105770000015ded6dc31a0000015ded6dc32b00000528000000080ac8c91d12dcd028ad96005000000603000000ff000b03c003000a38334ace02190000015ded6dc31a0000015ded6dc32b000009b70000000712dcd0280ac8c91d0050ad9600000603000000ff000b03c003000a1745a14812190000015ded6dd6b80000015ded6dd6c300000528000000080ac8c91d12dcd028ad98005000000603000000ff000b03c003000a85b1530202190000015ded6dd6b90000015ded6dd6c3000009b70000000712dcd0280ac8c91d0050ad9800000603000000ff000b03c003000a3f3b674812190000015ded6dea500000015ded6dea5b00000531000000080ac8c91d12dcd028ad9a005000000603000000ff000b03c003000a026c56b402190000015ded6dea510000015ded6dea5b000009b70000000712dcd0280ac8c91d0050ad9a00000603000000ff000b03c003000acb867d0e12190000015ded6dfde80000015ded6dfdf200000531000000080ac8c91d12dcd028ad9c005000000603000000ff000b03c003000acb4dc8f502190000015ded6dfde90000015ded6dfdf2000009b70000000712dcd0280ac8c91d0050ad9c00000603000000ff000b03c003000a74f818c812190000015ded6e11800000015ded6e119400000528000000080ac8c91d12dcd028ad9e005000000603000000ff000b03c003000a929f7b7402190000015ded6e11800000015ded6e1194000009b70000000712dcd0280ac8c91d0050ad9e00000603000000ff000b03c003000ac86498bf12190000015ded6e25210000015ded6e252f0000052d000000080ac8c91d12dcd028ada0005000000603000000ff000b03c003000adbea55d802190000015ded6e25220000015ded6e252f000009b70000000712dcd0280ac8c91d0050ada000000603000000ff000b03c003000a886d0ec012190000015ded6e38b90000015ded6e38c400000528000000080ac8c91d12dcd028ada2005000000603000000ff000b03c003000a3dae2bc102190000015ded6e38ba0000015ded6e38c4000009b70000000712dcd0280ac8c91d0050ada200000603000000ff000b03c003000a452f533212190000015ded6e4c510000015ded6e4c6400000528000000080ac8c91d12dcd028ada4005000000603000000ff000b03c003000a0dbf625a02190000015ded6e4c510000015ded6e4c64000009b70000000712dcd0280ac8c91d0050ada400000603000000ff000b03c003000a3e60ed8012190000015ded69afe90000015ded69afe900000164000000010ac8c9010ac8c91d00000303000001010000c0ff0001030000015ded69afe80000015ded69bb7700000290000000020ac8c91d0ac8c9010044004300011101000000ff0001030000015ded69bb770000015ded69bb7700000166000000010ac8c9010ac8c91d0043004400001101000010ff0001030000015ded6e5fed0000015ded6e5ff800000528000000080ac8c91d12dcd028ada6005000000603000000ff000b03c003000a396b41ae02190000015ded6e5fee0000015ded6e5ff8000009b70000000712dcd0280ac8c91d0050ada600000603000000ff000b03c003000ae064716712190000015ded6e73860000015ded6e73980000052d000000080ac8c91d12dcd028ada8005000000603000000ff000b03c003000a2d7a9ea002190000015ded6e73860000015ded6e7398000009b70000000712dcd0280ac8c91d0050ada800000603000000ff000b03c003000ad64507af12190000015ded6e87250000015ded6e87300000052d000000080ac8c91d12dcd028adaa005000000603000000ff000b03c003000ae954052702190000015ded6e87260000015ded6e8730000009b70000000712dcd0280ac8c91d0050adaa00000603000000ff000b03c003000a4d792e001219';

const IXIA_PACKET = '000a04c663c196a602a4dda200000000000201940100003a000100080002000800040001000600010007000200080004000a0004000b0002000c0004000e0004001000040011000400200002802000020000727900880001009800080099000801ceffff806e000400000bee806fffff00000bee8078000400000bee8079ffff00000bee807a000400000bee807bffff00000bee807dffff00000bee807e000400000bee807f000400000bee808c000400000bee808dffff00000bee808e000400000bee808fffff00000bee8091ffff00000bee8092000400000bee8093000400000bee80a0000100000bee80a1ffff00000bee80a2000100000bee80a3ffff00000bee80b0000800000bee80b1000800000bee80b2ffff00000bee80b3ffff00000bee80b4000200000bee80b6ffff00000bee80b7ffff00000bee80b8ffff00000bee80b9ffff00000bee80bc000400000bee80bdffff00000bee80beffff00000bee80bfffff00000bee80c3ffff00000bee80c5ffff00000bee80ca000600000bee80cb000600000bee80ccffff00000bee80cf000400000bee80d0ffff00000bee000201940101003a0001000800020008000400010006000100070002000a0004000b0002000e00040010000400110004001b0010001c001000880001008b0002808b000200007279009800080099000801ceffff806e000400000bee806fffff00000bee8078000400000bee8079ffff00000bee807a000400000bee807bffff00000bee807dffff00000bee807e000400000bee807f000400000bee808c000400000bee808dffff00000bee808e000400000bee808fffff00000bee8091ffff00000bee8092000400000bee8093000400000bee80a0000100000bee80a1ffff00000bee80a2000100000bee80a3ffff00000bee80b0000800000bee80b1000800000bee80b2ffff00000bee80b3ffff00000bee80b4000200000bee80b6ffff00000bee80b7ffff00000bee80b8ffff00000bee80b9ffff00000bee80bc000400000bee80bdffff00000bee80beffff00000bee80bfffff00000bee80c3ffff00000bee80c5ffff00000bee80ca000600000bee80cb000600000bee80ccffff00000bee80cf000400000bee80d0ffff00000bee00020024010200050055000801c9000201cbffff80b8ffff00000bee80c4000400000bee000200200103000380c6ffff00000bee80c7000400000bee80c8001000000bee000200180104000280cd000800000bee80ce000100000bee0003001e010500050001015a0004012f000201530001015800010155ffff01000114000000000000009a00000000000000021100c7f30a1482850000000100350a09b433000000010000000000000000000000000100000185ac34506b00000185ac34506b000000000106646f6d61696e5f5000000a507269766174652d4950000000000831302e2a2e2a2e2a07756e6b6e6f776e00000000000000005f5000000a507269766174652d4950000000000831302e2a2e2a2e2a07756e6b6e6f776e00000000000000000007756e6b6e6f776e00012d00000000000000f6000000000000000209436c65617274657874046e6f6e65000000000000000000ff1264656275672e6f70656e646e732e636f6d2e0002494e0303010203030103000000000000000000000000030301040000000000';

describe('NetFlowV9', function () {
    let netFlowV9;

    beforeEach(function () {
        // construct a new netflow object for each test to ensure we have empty templates
        netFlowV9 = new NetFlowV9({});
    });

    it('should be a function', function () {
        expect(NetFlowV9).to.be.a('function'); // is actually a constructor
    });

    it('should have nfPktDecode', function () {
        expect(netFlowV9).to.have.property('nfPktDecode');
    });

    describe('nfPktDecode', function () {
        it('should be able to decode vyos packet', function () {
            const buffer = Buffer.from(VYOS_PACKET, 'hex');
            expect(buffer).to.have.length(VYOS_PACKET.length/2);

            const rinfo = { address: '127.0.0.1', port: 2055 };
            const r = netFlowV9.nfPktDecode(buffer, rinfo);
            expect(netFlowV9.templates).to.have.property('127.0.0.1:2055');

            const testTemplates = netFlowV9.templates['127.0.0.1:2055'];
            expect(testTemplates).to.have.property('1024');
            expect(testTemplates).to.have.property('1025');
            expect(testTemplates).to.have.property('2048');
            expect(testTemplates).to.have.property('2049');

            expect(r).to.have.property('header');
            expect(r).to.have.property('flows');

            const header = r.header;
            expect(header).to.have.property('version', 9);
            expect(header).to.have.property('count', 7);
            expect(header).to.have.property('uptime', 152731);
            expect(header).to.have.property('seconds', 1404209570);
            expect(header).to.have.property('sequence', 1);
            expect(header).to.have.property('sourceId', 0);

            const flows = r.flows;
            expect(flows).to.have.length(2);

            const optionsFlow = flows[0];
            expect(optionsFlow).to.have.property('isOption', true);
            expect(optionsFlow).to.have.property('fsId', 4096);
            expect(optionsFlow).to.have.property('flow_sampler_id', 1);
            expect(optionsFlow).to.have.property('flow_sampler_mode', 2);

            const f1 = flows[1];
            expect(f1).to.have.property('ipv4_src_addr', '10.100.0.84');
            expect(f1).to.have.property('ipv4_dst_addr', '192.0.76.2');
            expect(f1).to.have.property('in_pkts', 1);
            //TODO:test everything
        });

        it('should be able to decode SonicWall IPFIX template and data packets', function () {
            const template = Buffer.from(SONICWALL_TEMPLATE, 'hex');
            expect(template).to.have.length(SONICWALL_TEMPLATE.length / 2);

            const rinfo = { address: '127.0.0.1', port: 2055 };
            netFlowV9.nfPktDecode(template, rinfo);
            expect(netFlowV9.templates).to.have.property('127.0.0.1:2055');

            const testTemplates = netFlowV9.templates['127.0.0.1:2055'];
            expect(testTemplates).to.have.property('256');

            const data = Buffer.from(SONICWALL_DATA, 'hex');
            expect(data).to.have.length(SONICWALL_DATA.length / 2);

            const r = netFlowV9.nfPktDecode(data, rinfo);

            const header = r.header;
            expect(header).to.have.property('version', 10);
            expect(header).to.have.property('length', 285);

            expect(header).to.have.property('exportTime', 1533773509);
            expect(header).to.have.property('sequence', 44272);
            expect(header).to.have.property('sourceId', 2692647936);

            const flows = r.flows;
            expect(flows).to.have.length(5);

            const f0 = flows[0];
            expect(f0).to.have.property('ipv4_src_addr', '172.217.2.37');
            expect(f0).to.have.property('ipv4_dst_addr', '10.0.0.237');
            expect(f0).to.have.property('in_pkts', 762);

            const f1 = flows[1];
            expect(f1).to.have.property('in_bytes', 157);
            expect(f1).to.have.property('protocol', 17);
            expect(f1).to.have.property('postNATSourceIPv4Address', '75.75.75.75');
        });


        it('should be able to decode Cisco SDWAN IPFIX template and data packets', function () {
            const template = Buffer.from(CISCO_TEMPLATE, 'hex');
            expect(template).to.have.length(CISCO_TEMPLATE.length / 2);

            const rinfo = { address: '127.0.0.1', port: 2055 };
            netFlowV9.nfPktDecode(template, rinfo);
            expect(netFlowV9.templates).to.have.property('127.0.0.1:2055');

            const testTemplates = netFlowV9.templates['127.0.0.1:2055'];
            expect(testTemplates).to.have.property('266');

            const data = Buffer.from(CISCO_DATA, 'hex');
            expect(data).to.have.length(CISCO_DATA.length / 2);

            const r = netFlowV9.nfPktDecode(data, rinfo);
            const header = r.header;
            expect(header).to.have.property('version', 10);
            expect(header).to.have.property('length', 104);
            expect(header).to.have.property('exportTime', 1669195195);
            expect(header).to.have.property('sequence', 453735);
            expect(header).to.have.property('sourceId', 1024);

            const flows = r.flows;
            expect(flows).to.have.length(1);

            const f0 = flows[0];
            expect(f0).to.have.property('ipv4_src_addr', '142.250.69.238');
            expect(f0).to.have.property('ipv4_dst_addr', '10.1.4.206');
            expect(f0).to.have.property('in_pkts', 1);
            expect(f0).to.have.property('in_bytes', 53);
            expect(f0).to.have.property('protocol', 17);
            expect(f0).to.have.property('connection_id_long', 13395372632464237000);
            expect(f0).to.have.property('egressoverlaysessionid', 6403);
        });

        it('should be able to decode YAF IPFIX template, options and data packets', function () {
            const template = Buffer.from(YAF_TEMPLATE, 'hex');
            expect(template).to.have.length(YAF_TEMPLATE.length / 2);

            const rinfo = { address: '127.0.0.1', port: 2055 };
            netFlowV9.nfPktDecode(template, rinfo);
            expect(netFlowV9.templates).to.have.property('127.0.0.1:2055');

            const testTemplates = netFlowV9.templates['127.0.0.1:2055'];
            // console.log(testTemplates)
            // templates from set 1
            expect(testTemplates).to.have.property('49171');
            expect(testTemplates).to.have.property('49173');
            expect(testTemplates).to.have.property('45825');
            expect(testTemplates).to.have.property('49176');
            expect(testTemplates).to.have.property('47104');
            expect(testTemplates).to.have.property('49155');

            // options templates from set 2
            expect(testTemplates).to.have.property('53248');
            expect(testTemplates).to.have.property('53249');

            // templates from set 3
            expect(testTemplates).to.have.property('53250');
            expect(testTemplates).to.have.property('49156');
            expect(testTemplates).to.have.property('49157');
            expect(testTemplates).to.have.property('49161');
            expect(testTemplates).to.have.property('49160');

            const data = Buffer.from(YAF_DATA, 'hex');
            expect(data).to.have.length(YAF_DATA.length / 2);

            const r = netFlowV9.nfPktDecode(data, rinfo);
            const header = r.header;
            expect(header).to.have.property('version', 10);
            expect(header).to.have.property('length', 1415);

            expect(header).to.have.property('exportTime', 1533765877);
            expect(header).to.have.property('sequence', 34994);
            expect(header).to.have.property('sourceId', 0);

            const flows = r.flows;
            expect(flows).to.have.length(25);

            const f0 = flows[0];
            expect(f0).to.have.property('ipv4_src_addr', '10.200.201.29');
            expect(f0).to.have.property('ipv4_dst_addr', '18.220.208.40');

            expect(f0).to.have.property('l4_src_port', 44438);
            expect(f0).to.have.property('l4_dst_port', 80);
            expect(f0).to.have.property('in_permanent_bytes', 1320);
            expect(f0).to.have.property('in_permanent_pkts', 8);
            expect(f0).to.have.property('unknown_type_293', '03c003000a38334ace0219');

            const f24 = flows[24];

            expect(f24).to.have.property('flowEndMilliseconds', 1502927030064);
            expect(f24).to.have.property('in_permanent_bytes', 2487);
            expect(f24).to.have.property('in_permanent_pkts', 7);
            expect(f24).to.have.property('ipv4_src_addr', '18.220.208.40');
            expect(f24).to.have.property('ipv4_dst_addr', '10.200.201.29');
            expect(f24).to.have.property('l4_src_port', 80);
            expect(f24).to.have.property('l4_dst_port', 44458);
            expect(f24).to.have.property('unknown_type_6871_40', '0000');
            expect(f24).to.have.property('protocol', 6);
            expect(f24).to.have.property('flowEndReason', 3);
            expect(f24).to.have.property('src_vlan', 0);
            expect(f24).to.have.property('src_tos', 0);
            expect(f24).to.have.property('unknown_type_293', '03c003000a4d792e001219');
            expect(f24).to.have.property('fsId', 45825);
        });

        it('should be able to decode IXIA IPFIX template, options and data packets', function () {
            const template = Buffer.from(IXIA_PACKET, 'hex');
            expect(template).to.have.length(IXIA_PACKET.length / 2);

            const rinfo = { address: '127.0.0.1', port: 2055 };
            const r = netFlowV9.nfPktDecode(template, rinfo);
            expect(netFlowV9.templates).to.have.property('127.0.0.1:2055');

            const testTemplates = netFlowV9.templates['127.0.0.1:2055'];
            expect(testTemplates).to.have.property('256');
            expect(testTemplates).to.have.property('257');
            expect(testTemplates).to.have.property('258');
            expect(testTemplates).to.have.property('259');
            expect(testTemplates).to.have.property('260');
            expect(testTemplates).to.have.property('261');

            const header = r.header;
            expect(header).to.have.property('version', 10);
            expect(header).to.have.property('length', 1222);

            expect(header).to.have.property('exportTime', 1673631398);
            expect(header).to.have.property('sequence', 44359074);
            expect(header).to.have.property('sourceId', 0);

            const flows = r.flows;
            expect(flows).to.have.length(1);

            const f0 = flows[0];
            expect(f0).to.have.property('ipv4_src_addr', '10.20.130.133');
            expect(f0).to.have.property('ipv4_dst_addr', '10.9.180.51');

            expect(f0).to.have.property('l4_src_port', 51187);
            expect(f0).to.have.property('l4_dst_port', 53);
            expect(f0).to.have.property('in_bytes', 154);
            expect(f0).to.have.property('in_pkts', 2);
            expect(f0).to.have.property('unknown_type_3054_110', '00000001');

            expect(f0).to.have.property('unknown_type_3054_189', '64656275672e6f70656e646e732e636f6d2e');
            const unknownType189AsString = Buffer.from(f0.unknown_type_3054_189, 'hex').toString('utf8');
            expect(unknownType189AsString).to.be.equal('debug.opendns.com.');
        });
    });
});
