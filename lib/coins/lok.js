"use strict";
const bignum = require('bignum');
const cnUtil = require('cryptoforknote-util');
const multiHashing = require('cryptonight-hashing');
const crypto = require('crypto');
const debug = require('debug')('coinFuncs');
const process = require('process');

let hexChars = new RegExp("[0-9a-f]+");

const reXMRig    = /XMRig(?:-[a-zA-Z]+)?\/(\d+)\.(\d+)\./; // 2.8.0
const reXMRSTAK  = /\w+-stak(?:-[a-zA-Z]+)?\/(\d+)\.(\d+)/; // 2.5.0
const reXMRSTAK2 = /\w+-stak(?:-[a-zA-Z]+)?\/(\d+)\.(\d+)\.(\d+)/; // 2.5.0
const reXNP      = /xmr-node-proxy\/(\d+)\.(\d+)\.(\d+)/; // 0.3.2
const reCAST     = /cast_xmr\/(\d+)\.(\d+)\.(\d+)/; // 1.5.0
const reSRB      = /SRBMiner Cryptonight AMD GPU miner\/(\d+)\.(\d+)\.(\d+)/; // 1.6.8

const pool_nonce_size = 16+1; // 1 extra byte for old XMR and new TRTL daemon bugs
const port2coin = {
    "11898": "TRTL",
    "22023": ""
};
const port2blob_num = {
    "11898": 2, // TRTL
    "18081": 0, // XMR
    "22023": 5 // LOKI
};
const mm_nonce_size = cnUtil.get_merged_mining_nonce_size();
const mm_port_set = { "22023": 11898 };

const extra_nonce_template_hex    = "02" + (pool_nonce_size + 0x100).toString(16).substr(-2) + "00".repeat(pool_nonce_size);
const extra_nonce_mm_template_hex = "02" + (mm_nonce_size + pool_nonce_size + 0x100).toString(16).substr(-2) + "00".repeat(mm_nonce_size + pool_nonce_size);

function get_coin2port(port2coin) {
    let coin2port = {};
    for (let port in port2coin) coin2port[port2coin[port]] = parseInt(port);
    return coin2port;
}
const coin2port = get_coin2port(port2coin);
function get_coins(port2coin) {
    let coins = [];
    for (let port in port2coin) if (port2coin[port] != "") coins.push(port2coin[port]);
    return coins;
}
const coins = get_coins(port2coin);
function get_mm_child_port_set(mm_port_set) {
    let mm_child_port_set = {};
    for (let port in mm_port_set) {
        const child_port = mm_port_set[port];
        if (!(child_port in mm_child_port_set)) mm_child_port_set[child_port] = {};
        mm_child_port_set[child_port][port] = 1;
    }
    return mm_child_port_set;
}
const mm_child_port_set = get_mm_child_port_set(mm_port_set);
                                                    
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
    this.donationMergeChildAddress = 'TRTLuxs1vbEMdQenWB8e7pFougBaL6qZcEcxfUb7j5q97zJWcVnk4HFbWi7UiT2CMbPU5Se2rsCycjf6LfUYZq3khXqweYjgXEv';
    this.donationMergAddress = 'L4yas7NfUhLLaYfusgR9rG7Y38Ypp94sPJunN6vB5Ma1HbcRVs7Ncm5YTmkpLKV7FDXf5uv3PdavhFwRDtS9deeYExBPkHU';

    this.blockedAddresses = [
        this.coinDevAddress,
        this.poolDevAddress
    ];
	
    this.donation = [
		{
			address: this.donationMergAddress,
			share:100,
			name:"pool"
		}
	];

    this.exchangeAddresses = [
        "LAQ84CunrmHVT83mARffDY46z5VcXyR1ZRAJoJHVpe8SjbzDZiEUkuA5oCnwf9yyGU1NizyXgvHzvVZr98Qfk1BU9fy11ZJ"
    
    ]; // These are addresses that MUST have a paymentID to perform logins with.

    this.prefix = 114;
    this.subPrefix = 116;
    this.intPrefix = 115;

    if (global.config.general.testnet === true){
        this.prefix = 24;
        this.subPrefix = 36;
        this.intPrefix = 25;
    }

    this.childPrefix = 3914525;
    this.childSubPrefix = 4222;
    this.childIntPrefix = 3914525;

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

    this.getPortAnyBlockHeaderByHash = function(port, blockHash, is_our_block, callback){
        // TRTL does not get getblock and XTL / LTHN / AEON have composite tx
        if (port == 11898 || port == 20189 || port == 48782 || port == 11181) {
            global.support.rpcPortDaemon(port, 'getblockheaderbyhash', {"hash": blockHash}, function (body) {
                if (typeof(body) === 'undefined' || !body.hasOwnProperty('result')) {
                    console.error(JSON.stringify(body));
                    return callback(true, body);
                }
                return callback(null, body.result.block_header);
            });
        } else global.support.rpcPortDaemon(port, 'getblock', {"hash": blockHash}, function (body) {
            if (typeof(body) === 'undefined' || !body.hasOwnProperty('result')) {
                console.error(JSON.stringify(body));
                return callback(true, body);
            }

            body.result.block_header.reward = 0;

            let reward_check = 0;
            const blockJson = JSON.parse(body.result.json);
            const minerTx = blockJson.miner_tx;

            if (port == 22023 || port == 31014 || port == 24182) { // Loki / Saronite / TUBE has reward as zero transaction
                reward_check = minerTx.vout[0].amount;
            } else {
                for (var i=0; i<minerTx.vout.length; i++) {
                    if (minerTx.vout[i].amount > reward_check) {
                        reward_check = minerTx.vout[i].amount;
                    }
                }
            }

            if (is_our_block && body.result.hasOwnProperty('miner_tx_hash')) global.support.rpcWallet("get_transfer_by_txid", {"txid": body.result.miner_tx_hash}, function (body2) {
                if (typeof(body2) === 'undefined' || body2.hasOwnProperty('error') || !body2.hasOwnProperty('result') || !body2.result.hasOwnProperty('transfer') || !body2.result.transfer.hasOwnProperty('amount')) {
                    console.error(port + ": block hash: " + blockHash + ": txid " + body.result.miner_tx_hash + ": " + JSON.stringify(body2));
                    return callback(true, body.result.block_header);
                }
                const reward = body2.result.transfer.amount;

                if (reward !== reward_check) {
                    console.error("Block reward does not match wallet reward: " + JSON.stringify(body) + "\n" + JSON.stringify(body2));
                    return callback(true, body);
                }

                body.result.block_header.reward = reward;
                return callback(null, body.result.block_header);

            }); else {
                body.result.block_header.reward = reward_check;
                return callback(null, body.result.block_header);
            }
        }); 
    };

    this.getPortBlockHeaderByHash = function(port, blockHash, callback){
        return this.getPortAnyBlockHeaderByHash(port, blockHash, true, callback);
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
            reserve_size: port in mm_port_set ? mm_nonce_size + pool_nonce_size : pool_nonce_size,
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

    this.validatePlainAddress = function(address, isChild){
        // This function should be able to be called from the async library, as we need to BLOCK ever so slightly to verify the address.
        address = new Buffer(address);
        let code = cnUtil.address_decode(address);
        return code === (isChild ? this.childPrefix : this.prefix) || code === (isChild ? this.childSubPrefix : this.subPrefix);
    };

    this.validateAddress = function(address, isChild){
        if (this.validatePlainAddress(address, isChild)) return true;
        // This function should be able to be called from the async library, as we need to BLOCK ever so slightly to verify the address.
		if (isChild && address.length === 187 && address.substring(0, 4) == 'TRTL') {return true};
        address = new Buffer(address);
        return cnUtil.address_decode_integrated(address) === (isChild ? this.childIntPrefix : this.intPrefix);
    };

    this.portBlobType = function(port, version) { return port2blob_num[port]; }

    this.convertBlob = function(blobBuffer, port){
        return cnUtil.convert_blob(blobBuffer, this.portBlobType(port, blobBuffer[0]));
    };

    this.constructNewBlob = function(blockTemplate, NonceBuffer, port){
        return cnUtil.construct_block_blob(blockTemplate, NonceBuffer, this.portBlobType(port, blockTemplate[0]));
    };

    this.constructMMParentBlockBlob = function(parentTemplateBuffer, port, childTemplateBuffer) {
        //console.log("MERGED MINING: constructMMParentBlockBlob");
        return cnUtil.construct_mm_parent_block_blob(parentTemplateBuffer, this.portBlobType(port, parentTemplateBuffer[0]), childTemplateBuffer);
    };

    this.constructMMChildBlockBlob = function(shareBuffer, port, childTemplateBuffer) {
        console.log("MERGED MINING: constructMMChildBlockBlob");
        return cnUtil.construct_mm_child_block_blob(shareBuffer, this.portBlobType(port, shareBuffer[0]), childTemplateBuffer);
    };

    this.getBlockID = function(blockBuffer, port){
        return cnUtil.get_block_id(blockBuffer, this.portBlobType(port, blockBuffer[0]));
    };

    this.BlockTemplate = function(template) {
        // Generating a block template is a simple thing.  Ask for a boatload of information, and go from there.
        // Important things to consider.
        // The reserved space is 16 bytes long now in the following format:
        // Assuming that the extraNonce starts at byte 130:
        // |130-133|134-137|138-141|142-145|
        // |minerNonce/extraNonce - 4 bytes|instanceId - Z4 bytes|clientPoolNonce - 4 bytes|clientNonce - 4 bytes|
        // This is designed to allow a single block template to be used on up to 4 billion poolSlaves (clientPoolNonce)
        // Each with 4 billion clients. (clientNonce)
        // While being unique to this particular pool thread (instanceId)
        // With up to 4 billion clients (minerNonce/extraNonce)
        // Overkill? Sure. But that's what we do here. Overkill.

        // Set these params equal to values we get from upstream.
        this.blocktemplate_blob = template.blocktemplate_blob;
        this.difficulty         = template.difficulty;
        this.height             = template.height;
        this.coin               = template.coin;
        this.port               = template.port;

        const is_mm = "child_template" in template;

        if (is_mm) {
            this.child_template        = template.child_template;
            this.child_template_buffer = template.child_template_buffer;
        }

        const blob = is_mm ? template.parent_blocktemplate_blob : template.blocktemplate_blob;

        this.idHash = crypto.createHash('md5').update(blob).digest('hex');

        // Set this.buffer to the binary decoded version of the BT blob
        this.buffer = new Buffer(blob, 'hex');

        const template_hex = (template.port in mm_port_set && !is_mm) ? extra_nonce_mm_template_hex : extra_nonce_template_hex;
        const found_reserved_offset_template = blob.indexOf(template_hex);

        if (found_reserved_offset_template !== -1) {
            const found_reserved_offset = (found_reserved_offset_template >> 1) + 2;
            if (is_mm) {
                this.reserved_offset = found_reserved_offset;
            } else {
                // here we are OK with +1 difference because we put extra byte into pool_nonce_size
                if (found_reserved_offset != template.reserved_offset && found_reserved_offset + 1 != template.reserved_offset) {
                    console.error("INTERNAL ERROR: Found reserved offset " + found_reserved_offset + " do not match " + template.reserved_offset + " reported by daemon in block " + ": " + blob);
                }
                this.reserved_offset = template.reserved_offset;
            }
        } else {
            console.error("INTERNAL ERROR: Can not find reserved offset template '" + template_hex + "' in block " + ": " + blob);
            this.reserved_offset = template.reserved_offset;
        }

        if (!("prev_hash" in template)) {  // Get prev_hash from blob
            let prev_hash = new Buffer(32);
            this.buffer.copy(prev_hash, 0, 7, 39);
            this.prev_hash = prev_hash.toString('hex');
        } else {
            this.prev_hash = template.prev_hash;
        }

        // Copy the Instance ID to the reserve offset + 4 bytes deeper.  Copy in 4 bytes.
        instanceId.copy(this.buffer, this.reserved_offset + 4, 0, 4);
        // Reset the Nonce - this is the per-miner/pool nonce
        this.extraNonce = 0;
        // The clientNonceLocation is the location at which the client pools should set the nonces for each of their clients.
        this.clientNonceLocation = this.reserved_offset + 12;
        // The clientPoolLocation is for multi-thread/multi-server pools to handle the nonce for each of their tiers.
        this.clientPoolLocation = this.reserved_offset + 8;

        this.nextBlob = function () {
            // Write a 32 bit integer, big-endian style to the 0 byte of the reserve offset.
            this.buffer.writeUInt32BE(++this.extraNonce, this.reserved_offset);
            // Convert the buffer into something hashable.
            return global.coinFuncs.convertBlob(this.buffer, this.port).toString('hex');
        };
        // Make it so you can get the raw block buffer out.
        this.nextBlobWithChildNonce = function () {
            // Write a 32 bit integer, big-endian style to the 0 byte of the reserve offset.
            this.buffer.writeUInt32BE(++this.extraNonce, this.reserved_offset);
            // Don't convert the buffer to something hashable.  You bad.
            return this.buffer.toString('hex');
        };
    };

    this.getCOINS          = function() { return coins; }
    this.PORT2COIN         = function(port) { return port2coin[port]; }
    this.COIN2PORT         = function(coin) { return coin2port[coin]; }
    this.getMM_PORTS       = function() { return mm_port_set; }
    this.getMM_CHILD_PORTS = function() { return mm_child_port_set; }

    this.getDefaultAlgos = function() {
        return [ "cn-pico/trtl" ];
    }

    this.getDefaultAlgosPerf = function() {
        return { "cn": 1, "cn/half": 1.9, "cn/rwz": 1.3, "cn/zls": 1.3, "cn/double": 0.5 };
    }

    this.convertAlgosToCoinPerf = function(algos_perf) {
        let coin_perf = {};

        if      ("cn/r" in algos_perf)          coin_perf[""]     = coin_perf["LTHN"] = coin_perf["WOW"]  = algos_perf["cn/r"];
        else if ("cn" in algos_perf)            coin_perf[""]     = coin_perf["LTHN"] = coin_perf["WOW"]  = algos_perf["cn"];
        else if ("cn/4" in algos_perf)          coin_perf[""]     = coin_perf["LTHN"] = coin_perf["WOW"]  = algos_perf["cn/4"];
        else if ("cn/wow" in algos_perf)        coin_perf[""]     = coin_perf["LTHN"] = coin_perf["WOW"]  = algos_perf["cn/wow"];

        if (!("" in coin_perf)) return "algo-perf set must include cn or cn/r hashrate";

        if      ("cn/half" in algos_perf)       coin_perf["MSR"]  = coin_perf["XTL"] = algos_perf["cn/half"];
        else if ("cn/fast2" in algos_perf)      coin_perf["MSR"]  = coin_perf["XTL"] = algos_perf["cn/fast2"];
        else if ("cn/xtlv9" in algos_perf)      coin_perf["XTL"]  = algos_perf["cn/xtlv9"];

        if      ("cn/gpu" in algos_perf)        coin_perf["RYO"]  = algos_perf["cn/gpu"];

        if      ("cn/wow" in algos_perf)        coin_perf["WOW"]  = algos_perf["cn/wow"];

        if      ("cn/rwz" in algos_perf)        coin_perf["GRFT"]  = algos_perf["cn/rwz"];

        if      ("cn-heavy" in algos_perf)      coin_perf["XRN"] = coin_perf["TUBE"] = coin_perf["XHV"] = algos_perf["cn-heavy"];
        else if ("cn-heavy/0" in algos_perf)    coin_perf["XRN"] = coin_perf["TUBE"] = coin_perf["XHV"] = algos_perf["cn-heavy/0"];

        if      ("cn-heavy/tube" in algos_perf) coin_perf["TUBE"] = algos_perf["cn-heavy/tube"];

        if      ("cn-heavy/xhv" in algos_perf)  coin_perf["XHV"]  = algos_perf["cn-heavy/xhv"];

        if      ("cn-lite" in algos_perf)       coin_perf["AEON"] = algos_perf["cn-lite"];
        else if ("cn-lite/1" in algos_perf)     coin_perf["AEON"] = algos_perf["cn-lite/1"];

        if      ("cn-pico"      in algos_perf)  coin_perf["LOKI"] = coin_perf["TRTL"] = algos_perf["cn-pico"];
        else if ("cn-pico/trtl" in algos_perf)  coin_perf["LOKI"] = coin_perf["TRTL"] = algos_perf["cn-pico/trtl"];

        return coin_perf;
    }

    // returns true if algo array reported by miner is OK or error string otherwise
    this.algoCheck = function(algos) {
        return algos.includes("cn-pico/trtl") || algos.includes("cryptonight-pico/trtl") ?
            true : "algo array must include cn-lite/1 or cn-pico/trtl";
    }

    this.cryptoNight = function(convertedBlob, port, height) {
        switch (port) {
            case 11898: return multiHashing.cryptonight_pico(convertedBlob, 0);		// TRTL
            case 22023: return multiHashing.cryptonight_pico(convertedBlob, 0);		// LOKI
            default:
		console.error("Unknown " + port + " port for PoW type on " + height + " height");
		return multiHashing.cryptonight(convertedBlob, 8);
        }
    }

    this.blobTypeStr = function(port, version) {
        switch (port) {
            case 11898: return "forknote2";       // TRTL
            case 22023: return "cryptonote_loki"; // LOKI
            default:    return "cryptonote";
        }
    }

    this.algoShortTypeStr = function(port, version) {
        switch (port) {
            case 11898: return "cn-pico/trtl";  // TRTL
            case 22023: return "cn-pico/trtl";  // LOKI
            default:
		console.error("Unknown " + port + " port for PoW type on " + version + " version");
	        return "cn/r";
        }
    }

    this.isMinerSupportAlgo = function(algo, algos) {
        if (algo in algos) return true;
        if (algo === "cn-heavy/0" && "cn-heavy" in algos) return true;
        return false;
    }

    this.get_miner_agent_notification = function(agent) {
        let m;
        return false;
    };
    
    this.get_miner_agent_warning_notification = function(agent) {
        let m;
        if (m = reXMRig.exec(agent)) {
            const majorv = parseInt(m[1]) * 10000;
            const minorv = parseInt(m[2]) * 100;
            if (majorv + minorv < 21000) {
                return "Please update your XMRig miner (" + agent + ") to v2.10.0+ to support new algo";
            }
        } else if (m = reXMRSTAK2.exec(agent)) {
            const majorv = parseInt(m[1]) * 10000;
            const minorv = parseInt(m[2]) * 100;
            const minorv2 = parseInt(m[3]);
            if (majorv + minorv + minorv2 < 20800) {
                return "Please update your xmr-stak miner (" + agent + ") to v2.8.0+ and use cryptonight_turtle in config to support new algo";
            }
        } else if (m = reXNP.exec(agent)) {
            const majorv = parseInt(m[1]) * 10000;
            const minorv = parseInt(m[2]) * 100;
            const minorv2 = parseInt(m[3]);
            const version = majorv + minorv + minorv2;
            if (version < 801) {
                 return "Please update your xmr-node-proxy (" + agent + ") to version v0.9.0+ by doing 'cd xmr-node-proxy && ./update.sh' (or check https://github.com/MoneroOcean/xmr-node-proxy repo)";
            }
        } else if (m = reSRB.exec(agent)) {
            const majorv = parseInt(m[1]) * 10000;
            const minorv = parseInt(m[2]) * 100;
            const minorv2 = parseInt(m[3]);
            if (majorv + minorv + minorv2 < 10704) {
                 return "Please update your SRBminer (" + agent + ") to version v1.7.4+ to support new algo";
            }
        }
        return false;
    };
}

module.exports = Coin;
