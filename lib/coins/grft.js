"use strict";
const bignum = require('bignum');
const cnUtil = require('cryptoforknote-util');
const multiHashing = require('cryptonight-hashing');
const crypto = require('crypto');
const debug = require('debug')('coinFuncs');
const process = require('process');

let hexChars = new RegExp("[0-9a-f]+");

const reXMRig    = /XMRig(?:-[a-zA-Z]+)?\/(\d+)\.(\d+)\./; // 2.8.0
const reXMRSTAK  = /xmr-stak(?:-[a-zA-Z]+)?\/(\d+)\.(\d+)/; // 2.5.0
const reXMRSTAK2 = /xmr-stak(?:-[a-zA-Z]+)?\/(\d+)\.(\d+)\.(\d+)/; // 2.5.0
const reXNP      = /xmr-node-proxy\/(\d+)\.(\d+)\.(\d+)/; // 0.3.2
const reCAST     = /cast_xmr\/(\d+)\.(\d+)\.(\d+)/; // 1.5.0
const reSRB      = /SRBMiner Cryptonight AMD GPU miner\/(\d+)\.(\d+)\.(\d+)/; // 1.6.8
                                                    
function Coin(data){
    this.bestExchange = global.config.payout.bestExchange;
    this.data = data;
    //let instanceId = crypto.randomBytes(4);
    let instanceId = new Buffer(4);
    instanceId.writeUInt32LE( ((global.config.pool_id % (1<<16)) << 16) + (process.pid  % (1<<16)) );
    console.log("Generated instanceId: " + instanceId.toString('hex'));
    this.testDevAddress = "41jrqvF7Cb7bU6SzL2pbaP4UrYTqf5wfHUqiMnNwztYg71XjbC2udj6hrN8b6npQyC2WUVFoXDViP3GFMZEYbUgR9TwJX6B";  // Address for live pool testing
    this.coinDevAddress = global.config.payout.feeAddress;
    this.poolDevAddress = global.config.payout.feeAddress;

    this.blockedAddresses = [
        this.coinDevAddress,
        this.poolDevAddress 
    ];

    this.exchangeAddresses = [
        
    ]; // These are addresses that MUST have a paymentID to perform logins with.

    this.prefix = 90;
    this.subPrefix = 4222;
    this.intPrefix = 91;

    if (global.config.general.testnet === true){
        this.prefix = 53;
        this.subPrefix = 63;
        this.intPrefix = 54;
    }

    this.supportsAutoExchange = false;

    this.niceHashDiff = 1000000;

    this.getPortBlockHeaderByID = function(port, blockId, callback){
        global.support.rpcPortDaemon(port, 'getblockheaderbyheight', {"height": blockId}, function (body) {
            if (body.hasOwnProperty('result')){
                return callback(null, body.result.block_header);
            } else {
                console.error(JSON.stringify(body));
                return callback(true, body);
            }
        });
    };

    this.getBlockHeaderByID = function(blockId, callback){
        return this.getPortBlockHeaderByID(global.config.daemon.port, blockId, callback);
    };

    this.getPortBlockHeaderByHash = function(port, blockHash, callback){
        global.support.rpcPortDaemon(port, port == 11898 ? 'getblockheaderbyhash' : 'getblock', {"hash": blockHash}, function (body) {
            if (typeof(body) !== 'undefined' && body.hasOwnProperty('result')) {

                if (port != 11898 && port != 20189 && port != 48782 && port != 11181 && port != 22023) { // Stellite/Intense/Aeon/loki have composite based miner_tx
                    const blockJson = JSON.parse(body.result.json);
                    body.result.block_header.reward = 0;

                    const minerTx = blockJson.miner_tx;

                    for (var i=0; i<minerTx.vout.length; i++) {
                        if (minerTx.vout[i].amount > body.result.block_header.reward) {
                            body.result.block_header.reward = minerTx.vout[i].amount;
                        }
                    }

                } else if (port == 22023) { // Loki has reward as zero transaction
                    const blockJson = JSON.parse(body.result.json);
                    body.result.block_header.reward = 0;

                    const minerTx = blockJson.miner_tx;

                    body.result.block_header.reward = minerTx.vout[0].amount;
                }

                return callback(null, body.result.block_header);
            } else {
                console.error(JSON.stringify(body));
                return callback(true, body);
            }
        });
    };

    this.getBlockHeaderByHash = function(blockHash, callback){
        return this.getPortBlockHeaderByHash(global.config.daemon.port, blockHash, callback);
    };

    this.getPortLastBlockHeader = function(port, callback, no_error_report){
        global.support.rpcPortDaemon(port, 'getlastblockheader', [], function (body) {
            if (typeof(body) !== 'undefined' && body.hasOwnProperty('result')){
                return callback(null, body.result.block_header);
            } else {
                if (!no_error_report) console.error(JSON.stringify(body));
                return callback(true, body);
            }
        });
    };

    this.getLastBlockHeader = function(callback){
        return this.getPortLastBlockHeader(global.config.daemon.port, callback);
    };

    this.getPortBlockTemplate = function(port, callback){
        global.support.rpcPortDaemon(port, 'getblocktemplate', {
            reserve_size: 17,
            wallet_address: global.config.pool[port == global.config.daemon.port ? "address" : "address_" + port.toString()]
        }, function(body){
            return callback(body);
        });
    };

    this.getBlockTemplate = function(callback){
        return this.getPortBlockTemplate(global.config.daemon.port, callback);
    };

    this.baseDiff = function(){
        return bignum('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 16);
    };

    this.validatePlainAddress = function(address){
        // This function should be able to be called from the async library, as we need to BLOCK ever so slightly to verify the address.
        address = new Buffer(address);
        let code = cnUtil.address_decode(address);
        return code === this.prefix || code === this.subPrefix;
    };

    this.validateAddress = function(address){
        if (this.validatePlainAddress(address)) return true;
        // This function should be able to be called from the async library, as we need to BLOCK ever so slightly to verify the address.
        address = new Buffer(address);
        return cnUtil.address_decode_integrated(address) === this.intPrefix;
    };

    this.portBlobType = function(port, version) {
        switch (port) {
            case 11898: return 2; // TRTL
            case 12211: return 4; // RYO
            case 22023: return 5; // LOKI
            case 38081: return 3; // MSR
            default:    return 0;
        }
    }

    this.convertBlob = function(blobBuffer, port){
        return cnUtil.convert_blob(blobBuffer, this.portBlobType(port, blobBuffer[0]));
    };

    this.constructNewBlob = function(blockTemplate, NonceBuffer, port){
        return cnUtil.construct_block_blob(blockTemplate, NonceBuffer, this.portBlobType(port, blockTemplate[0]));
    };

    this.getBlockID = function(blockBuffer, port){
        return cnUtil.get_block_id(blockBuffer, this.portBlobType(port, blockBuffer[0]));
    };

    this.BlockTemplate = function(template) {
        /*
        Generating a block template is a simple thing.  Ask for a boatload of information, and go from there.
        Important things to consider.
        The reserved space is 16 bytes long now in the following format:
        Assuming that the extraNonce starts at byte 130:
        |130-133|134-137|138-141|142-145|
        |minerNonce/extraNonce - 4 bytes|instanceId - 4 bytes|clientPoolNonce - 4 bytes|clientNonce - 4 bytes|
        This is designed to allow a single block template to be used on up to 4 billion poolSlaves (clientPoolNonce)
        Each with 4 billion clients. (clientNonce)
        While being unique to this particular pool thread (instanceId)
        With up to 4 billion clients (minerNonce/extraNonce)
        Overkill?  Sure.  But that's what we do here.  Overkill.
         */

        // Set this.blob equal to the BT blob that we get from upstream.
        this.blob = template.blocktemplate_blob;
        this.idHash = crypto.createHash('md5').update(template.blocktemplate_blob).digest('hex');
        // Set this.diff equal to the known diff for this block.
        this.difficulty = template.difficulty;
        // Set this.height equal to the known height for this block.
        this.height = template.height;
        // Set this.reserveOffset to the byte location of the reserved offset.
        this.reserveOffset = template.reserved_offset;
        // Set this.buffer to the binary decoded version of the BT blob.
        this.buffer = new Buffer(this.blob, 'hex');
        // Copy the Instance ID to the reserve offset + 4 bytes deeper.  Copy in 4 bytes.
        instanceId.copy(this.buffer, this.reserveOffset + 4, 0, 4);
        // Generate a clean, shiny new buffer.
        this.previous_hash = new Buffer(32);
        // Copy in bytes 7 through 39 to this.previous_hash from the current BT.
        this.buffer.copy(this.previous_hash, 0, 7, 39);
        // Reset the Nonce. - This is the per-miner/pool nonce
        this.extraNonce = 0;
        // The clientNonceLocation is the location at which the client pools should set the nonces for each of their clients.
        this.clientNonceLocation = this.reserveOffset + 12;
        // The clientPoolLocation is for multi-thread/multi-server pools to handle the nonce for each of their tiers.
        this.clientPoolLocation = this.reserveOffset + 8;
        // this is current coin
        this.coin = template.coin;
        // this is current daemon port
        this.port = template.port;
        this.nextBlob = function () {
            // Write a 32 bit integer, big-endian style to the 0 byte of the reserve offset.
            this.buffer.writeUInt32BE(++this.extraNonce, this.reserveOffset);
            // Convert the blob into something hashable.
            return global.coinFuncs.convertBlob(this.buffer, this.port).toString('hex');
        };
        // Make it so you can get the raw block blob out.
        this.nextBlobWithChildNonce = function () {
            // Write a 32 bit integer, big-endian style to the 0 byte of the reserve offset.
            this.buffer.writeUInt32BE(++this.extraNonce, this.reserveOffset);
            // Don't convert the blob to something hashable.  You bad.
            return this.buffer.toString('hex');
        };
    };

    this.getCOINS = function() {
        return [ ];
    }

    this.getDefaultAlgos = function() {
        return [ "cn/2" ];
    }

    this.getDefaultAlgosPerf = function() {
        return { "cn": 1, "cn/msr": 1.9 };
    }

    this.convertAlgosToCoinPerf = function(algos_perf) {
        let coin_perf = {};

        if      ("cn" in algos_perf)            coin_perf[""]     = coin_perf["GRFT"] = coin_perf["LTHN"] = algos_perf["cn"];
        else if ("cn/1" in algos_perf)          coin_perf[""]     = coin_perf["GRFT"] = coin_perf["LTHN"] = algos_perf["cn/1"];
        if      ("cn/2" in algos_perf)          coin_perf[""]     = coin_perf["LTHN"] = algos_perf["cn/2"];

        if (!("" in coin_perf)) return "algo_perf set must include cn, cn/1 or cn/2 hashrate";

        if      ("cn/xtl" in algos_perf)        coin_perf["XTL"]  = algos_perf["cn/xtl"];
        else                                    coin_perf["XTL"]  = "GRFT" in coin_perf ? coin_perf["GRFT"] : coin_perf[""];

        if      ("cn/msr" in algos_perf)        coin_perf["MSR"]  = algos_perf["cn/msr"];
        else if ("cn-fast" in algos_perf)       coin_perf["MSR"]  = algos_perf["cn-fast"];

        if      ("cn-heavy" in algos_perf)      coin_perf["RYO"]  = coin_perf["LOKI"] = coin_perf["TUBE"] = coin_perf["XHV"] = algos_perf["cn-heavy"];
        else if ("cn-heavy/0" in algos_perf)    coin_perf["RYO"]  = coin_perf["LOKI"] = coin_perf["TUBE"] = coin_perf["XHV"] = algos_perf["cn-heavy/0"];

        if      ("cn-heavy/tube" in algos_perf) coin_perf["TUBE"] = algos_perf["cn-heavy/tube"];

        if      ("cn-heavy/xhv" in algos_perf)  coin_perf["XHV"]  = algos_perf["cn-heavy/xhv"];

        if      ("cn-lite" in algos_perf)       coin_perf["AEON"] = coin_perf["TRTL"] = algos_perf["cn-lite"];
        else if ("cn-lite/1" in algos_perf)     coin_perf["AEON"] = coin_perf["TRTL"] = algos_perf["cn-lite/1"];

        return coin_perf;
    }

    // returns true if algo array reported by miner is OK or error string otherwise
    this.algoCheck = function(algos) {
        return algos.includes("cn/1") || algos.includes("cn/2") ?
               true : "algo array should include cn/1 or cn/2";
    }

    this.cryptoNight = function(convertedBlob, port) {
        switch (port) {
            case 11181: return multiHashing.cryptonight_light(convertedBlob, 1); // Aeon
            case 11898: return multiHashing.cryptonight_light(convertedBlob, 1); // TRTL
            case 12211: return multiHashing.cryptonight_heavy(convertedBlob, 0); // RYO
            case 17750: return multiHashing.cryptonight_heavy(convertedBlob, 1); // Haven
            case 18081: return multiHashing.cryptonight(convertedBlob, 8);       // XMR
            case 18981: return multiHashing.cryptonight(convertedBlob, convertedBlob[0] >= 11 ? 8 : 1);       // Graft
            case 20189: return multiHashing.cryptonight(convertedBlob, 3);       // Stellite
            case 22023: return multiHashing.cryptonight_heavy(convertedBlob, 0); // LOKI
            case 24182: return multiHashing.cryptonight_heavy(convertedBlob, 2); // BitTube
            case 38081: return multiHashing.cryptonight(convertedBlob, 4);       // MSR
            case 48782: return multiHashing.cryptonight(convertedBlob, 8);       // Lethean
            default:    return multiHashing.cryptonight(convertedBlob, 8);
        }
    }

    this.blobTypeStr = function(port, version) {
        switch (port) {
            case 11898: return "forknote2";       // TRTL
            case 12211: return "cryptonote_ryo";  // RYO
            case 22023: return "cryptonote_loki"; // LOKI
            case 38081: return "cryptonote2";     // MSR
            default:    return "cryptonote";
        }
    }

    this.algoShortTypeStr = function(port, version) {
        switch (port) {
            case 11181: return "cn-lite/1";     // Aeon
            case 11898: return "cn-lite/1";     // TRTL
            case 12211: return "cn-heavy/0";    // RYO
            case 17750: return "cn-heavy/xhv";  // Haven
            case 18081: return "cn/2";          // XMR
            case 18981: return version >= 11 ? "cn/2" : "cn/1";          // Graft
            case 20189: return "cn/xtl";        // Stellite
            case 22023: return "cn-heavy/0";    // LOKI
            case 24182: return "cn-heavy/tube"; // BitTube
            case 38081: return "cn/msr";        // MSR
            case 48782: return "cn/2";          // Lethean
            default:    return "cn/2";
        }
    }

    this.variantValue = function(port, version) {
        switch (port) {
            case 11181: return "1";    // Aeon
            case 11898: return "1";    // TRTL
            case 12211: return "0";    // RYO
            case 17750: return "xhv";  // Haven
            case 18081: return "2";    // XMR
            case 18981: return version >= 11 ? "2" : "1";    // Graft
            case 20189: return "xtl";  // Stellite
            case 22023: return "0";    // LOKI
            case 24182: return "tube"; // BitTube
            case 38081: return "msr";  // MSR
            case 48782: return "2";    // Lethean
            default:    return "2";
        }
    }

    this.isMinerSupportAlgo = function(algo, algos) {
        if (algo in algos) return true;
        if (algo === "cn-heavy/0" && "cn-heavy" in algos) return true;
        return false;
    }

    this.get_miner_agent_notification = function(agent) {
        let m;
        if (m = reXMRig.exec(agent)) {
            const majorv = parseInt(m[1]) * 10000;
            const minorv = parseInt(m[2]) * 100;
            if (majorv + minorv < 20600) {
                return "You must update your XMRig miner (" + agent + ") to v2.8.0+";
            }
        } else if (m = reXMRSTAK.exec(agent)) {
            const majorv = parseInt(m[1]) * 10000;
            const minorv = parseInt(m[2]) * 100;
            if (majorv + minorv < 20500) {
                return "You must update your xmr-stak miner (" + agent + ") to v2.5.0+ (and use cryptonight_v8 in config)";
            }
        } else if (m = reXNP.exec(agent)) {
            const majorv = parseInt(m[1]) * 10000;
            const minorv = parseInt(m[2]) * 100;
            const minorv2 = parseInt(m[3]);
            const version = majorv + minorv + minorv2;
            if (version < 3) {
                return "You must update your xmr-node-proxy (" + agent + ") to version v0.3.2+ (from https://github.com/MoneroOcean/xmr-node-proxy repo)";
            }
            if (version >= 100 && version < 202) {
                return "You must update your xmr-node-proxy (" + agent + ") to version v0.3.2+ (from https://github.com/MoneroOcean/xmr-node-proxy repo)";
            }
        } else if (m = reCAST.exec(agent)) {
            const majorv = parseInt(m[1]) * 10000;
            const minorv = parseInt(m[2]) * 100;
            const minorv2 = parseInt(m[3]);
            if (majorv + minorv + minorv2 < 10400) {
                 return "You must update your cast-xmr miner (" + agent + ") to version v1.5.0+ (and use --algo=10 command line switch)";
            }
        } else if (m = reSRB.exec(agent)) {
            const majorv = parseInt(m[1]) * 10000;
            const minorv = parseInt(m[2]) * 100;
            const minorv2 = parseInt(m[3]);
            if (majorv + minorv + minorv2 < 10607) {
                 return "You must update your SRBminer (" + agent + ") to version v1.6.8+";
            }
        }
        return false;
    };
    
    this.get_miner_agent_warning_notification = function(agent) {
        let m;
        /*if (m = reXMRig.exec(agent)) {
            const majorv = parseInt(m[1]) * 10000;
            const minorv = parseInt(m[2]) * 100;
            if (majorv + minorv < 20800) {
                return "Please update your XMRig miner (" + agent + ") to v2.8.0+";
            }
        } else if (m = reXMRSTAK2.exec(agent)) {
            const majorv = parseInt(m[1]) * 10000;
            const minorv = parseInt(m[2]) * 100;
            const minorv2 = parseInt(m[3]);
            if (majorv + minorv + minorv2 < 20500) {
                return "Please update your xmr-stak miner (" + agent + ") to v2.5.0+ (and use cryptonight_v8 in config)";
            }
        } else */if (m = reXNP.exec(agent)) {
            const majorv = parseInt(m[1]) * 10000;
            const minorv = parseInt(m[2]) * 100;
            const minorv2 = parseInt(m[3]);
            const version = majorv + minorv + minorv2;
            if (version < 302) {
                 return "Please update your xmr-node-proxy (" + agent + ") to version v0.3.2+ by doing 'cd xmr-node-proxy && ./update.sh' (or check https://github.com/MoneroOcean/xmr-node-proxy repo)";
            }
        } /*else if (m = reCAST.exec(agent)) {
            const majorv = parseInt(m[1]) * 10000;
            const minorv = parseInt(m[2]) * 100;
            const minorv2 = parseInt(m[3]);
            if (majorv + minorv + minorv2 < 10500) {
                 return "Please update your cast-xmr miner (" + agent + ") to version v1.5.0+";
            }
        } else if (m = reSRB.exec(agent)) {
            const majorv = parseInt(m[1]) * 10000;
            const minorv = parseInt(m[2]) * 100;
            const minorv2 = parseInt(m[3]);
            if (majorv + minorv + minorv2 < 10608) {
                 return "Please update your SRBminer (" + agent + ") to version v1.6.8+";
            }
        }*/
        return false;
    };
}

module.exports = Coin;