const {
    decNumRule,
    decTimestamp,
    decTsMs,
    decTsMcs,
    decTsNs,
    decIpv4Rule,
    decIpv6Rule,
    decMacRule,
    decStringRule,
    decAsciiStringRule,
} = require('../nf9/fieldRules');

const cisco = {
    12432: { name: 'ingressoverlaysessionid', compileRule: decNumRule },
    12433: { name: 'egressoverlaysessionid', compileRule: decNumRule },
    12434: { name: 'routing_vrf_service', compileRule: decNumRule },
    12441: { name: 'connection_id_long', compileRule: decNumRule },
    12442: { name: 'drop_cause_id', compileRule: decNumRule },
    12443: { name: 'counter_bytes_sdwan_dropped_long', compileRule: decNumRule },
    12444: { name: 'sdwan_sla_not_met', compileRule: decNumRule },
    12445: { name: 'sdwan_preferred_color_not_met', compileRule: decNumRule },
    12446: { name: 'sdwan_qos_queue_id', compileRule: decNumRule },
    42329: { name: 'counter_packets_sdwan_dropped_long', compileRule: decNumRule },
};

module.exports = {
    enterpriseTypes: {
        9: cisco,
    },
};
