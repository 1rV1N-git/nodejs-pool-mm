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
    "11181": "AEON",
    "11898": "TRTL",
    "12211": "RYO",
    "17750": "XHV",
    "18081": "",
    "18981": "GRFT",
    "20189": "XTL",
    "22023": "LOKI",
    "24182": "TUBE",
    "31014": "XRN",
    "34568": "WOW",
    "38081": "MSR",
    "48782": "LTHN"
};
const port2blob_num = {
    "11181": 0, // AEON
    "11898": 2, // TRTL
    "12211": 4, // RYO
    "17750": 0, // XHV
    "18081": 0, // XMR
    "18981": 0, // GRFT
    "20189": 0, // XTL
    "22023": 5, // LOKI
    "24182": 0, // TUBE
    "31014": 5, // XRN
    "34568": 0, // WOW
    "38081": 6, // MSR
    "48782": 0, // LTHN
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
    this.coinDevAddress = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A";  // Monero Developers Address
    this.poolDevAddress = "499fS1Phq64hGeqV8p2AfXbf6Ax7gP6FybcMJq6Wbvg8Hw6xms8tCmdYpPsTLSaTNuLEtW4kF2DDiWCFcw4u7wSvFD8wFWE";  // MoneroOcean Address

    this.blockedAddresses = [
        this.coinDevAddress,
        this.poolDevAddress,
        "43SLUTpyTgXCNXsL43uD8FWZ5wLAdX7Ak67BgGp7dxnGhLmrffDTXoeGm2GBRm8JjigN9PTg2gnShQn5gkgE1JGWJr4gsEU", // Wolf0's address
        "42QWoLF7pdwMcTXDviJvNkWEHJ4TXnMBh2Cx6HNkVAW57E48Zfw6wLwDUYFDYJAqY7PLJUTz9cHWB5C4wUA7UJPu5wPf4sZ", // Wolf0's address
        "46gq64YYgCk88LxAadXbKLeQtCJtsLSD63NiEc3XHLz8NyPAyobACP161JbgyH2SgTau3aPUsFAYyK2RX4dHQoaN1ats6iT", // Claymore's Fee Address.
        "47mr7jYTroxQMwdKoPQuJoc9Vs9S9qCUAL6Ek4qyNFWJdqgBZRn4RYY2QjQfqEMJZVWPscupSgaqmUn1dpdUTC4fQsu3yjN"  // Claymore's _other_ fee address.
    ];

    this.exchangeAddresses = [
        "46yzCCD3Mza9tRj7aqPSaxVbbePtuAeKzf8Ky2eRtcXGcEgCg1iTBio6N4sPmznfgGEUGDoBz5CLxZ2XPTyZu1yoCAG7zt6", // Shapeshift.io
        "463tWEBn5XZJSxLU6uLQnQ2iY9xuNcDbjLSjkn3XAXHCbLrTTErJrBWYgHJQyrCwkNgYvyV3z8zctJLPCZy24jvb3NiTcTJ", // Bittrex
        "44TVPcCSHebEQp4LnapPkhb2pondb2Ed7GJJLc6TkKwtSyumUnQ6QzkCCkojZycH2MRfLcujCM7QR1gdnRULRraV4UpB5n4", // Xmr.to
        "47sghzufGhJJDQEbScMCwVBimTuq6L5JiRixD8VeGbpjCTA12noXmi4ZyBZLc99e66NtnKff34fHsGRoyZk3ES1s1V4QVcB", // Poloniex
        "44tLjmXrQNrWJ5NBsEj2R77ZBEgDa3fEe9GLpSf2FRmhexPvfYDUAB7EXX1Hdb3aMQ9FLqdJ56yaAhiXoRsceGJCRS3Jxkn", // Binance.com
        "43c2ykU9i2KZHjV8dWff9HKurYYRkckLueYK96Qh4p1EDoEvdo8mpgNJJpPuods53PM6wNzmj4K2D1V11wvXsy9LMiaYc86", // Changelly.com
        "45rTtwU6mHqSEMduDm5EvUEmFNx2Z6gQhGBJGqXAPHGyFm9qRfZFDNgDm3drL6wLTVHfVhbfHpCtwKVvDLbQDMH88jx2N6w", // ?
        "4ALcw9nTAStZSshoWVUJakZ6tLwTDhixhQUQNJkCn4t3fG3MMK19WZM44HnQRvjqmz4LkkA8t565v7iBwQXx2r34HNroSAZ", // Cryptopia.co.nz
        "4BCeEPhodgPMbPWFN1dPwhWXdRX8q4mhhdZdA1dtSMLTLCEYvAj9QXjXAfF7CugEbmfBhgkqHbdgK9b2wKA6nqRZQCgvCDm", // Bitfinex
        "41xeYWWKwtSiHju5AdyF8y5xeptuRY3j5X1XYHuB1g6ke4eRexA1iygjXqrT3anyZ22j7DEE74GkbVcQFyH2nNiC3gJqjM9", // HitBTC 1
        "43Kg3mcpvaDhHpv8C4UWf7Kw2DAexn2NoRMqqM5cpAtuRgkedDZWjBQjXqrT3anyZ22j7DEE74GkbVcQFyH2nNiC3dx22mZ", // HitBTC 2
	"44rouyxW44oMc1yTGXBUsL6qo9AWWeHETFiimWC3TMQEizSqqZZPnw1UXCaJrCtUC9QT25L5MZvkoGKRxZttvbkmFXA3TMG", // BTC-Alpha 
        "45SLfxvu355SpjjzibLKaChA4NGoTrQAwZmSopAXQa9UXBT63BvreEoYyczTcfXow6eL8VaEG2X6NcTG67XZFTNPLgdR9iM", // some web wallet
    ]; // These are addresses that MUST have a paymentID to perform logins with.

    this.prefix = 18;
    this.subPrefix = 42;
    this.intPrefix = 19;

    if (global.config.general.testnet === true){
        this.prefix = 53;
        this.subPrefix = 63;
        this.intPrefix = 54;
    }

    this.supportsAutoExchange = true;

    this.niceHashDiff = 400000;

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

            if (is_our_block && body.result.hasOwnProperty('miner_tx_hash')) global.support.rpcPortWallet(port+1, "get_transfer_by_txid", {"txid": body.result.miner_tx_hash}, function (body2) {
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
        return [ "cn/r" ];
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
        return algos.includes("cn/r") ? true : "algo array must include cn/r";
    }

    this.cryptoNight = function(convertedBlob, port, height) {
        switch (port) {
            case 11181: return multiHashing.cryptonight_light(convertedBlob, 1);	// Aeon
            case 11898: return multiHashing.cryptonight_pico(convertedBlob, 0);		// TRTL
            case 12211: return multiHashing.cryptonight(convertedBlob, 11);		// RYO
            case 17750: return multiHashing.cryptonight_heavy(convertedBlob, 1);	// Haven
            case 18081: return multiHashing.cryptonight(convertedBlob, 13, height);	// XMR
            case 18981: return multiHashing.cryptonight(convertedBlob, 14);		// Graft
            case 20189: return multiHashing.cryptonight(convertedBlob, 9);		// Stellite
            case 22023: return multiHashing.cryptonight_pico(convertedBlob, 0);		// LOKI
            case 24182: return multiHashing.cryptonight_heavy(convertedBlob, 2);	// BitTube
            case 31014: return multiHashing.cryptonight_heavy(1);			// Saronite
            case 34568: return multiHashing.cryptonight(convertedBlob, 12, height);	// Wownero
            case 38081: return multiHashing.cryptonight(convertedBlob, 9);       	// MSR
            case 48782: return multiHashing.cryptonight(convertedBlob, 13, height);	// Lethean
            default:
		console.error("Unknown " + port + " port for PoW type on " + height + " height");
		return multiHashing.cryptonight(convertedBlob, 8);
        }
    }

    this.blobTypeStr = function(port, version) {
        switch (port) {
            case 11898: return "forknote2";       // TRTL
            case 12211: return "cryptonote_ryo";  // RYO
            case 22023: return "cryptonote_loki"; // LOKI
            case 31014: return "cryptonote_loki"; // Saronite
            case 38081: return "cryptonote3";     // MSR
            default:    return "cryptonote";
        }
    }

    this.algoShortTypeStr = function(port, version) {
        switch (port) {
            case 11181: return "cn-lite/1";     // Aeon
            case 11898: return "cn-pico/trtl";  // TRTL
            case 12211: return "cn/gpu";        // RYO
            case 17750: return "cn-heavy/xhv";  // Haven
            case 18081: return "cn/r";          // XMR
            case 18981: return "cn/rwz";        // Graft
            case 20189: return "cn/half";       // Stellite
            case 22023: return "cn-pico/trtl";  // LOKI
            case 24182: return "cn-heavy/tube"; // BitTube
            case 31014: return "cn-heavy/xhv";  // Saronite
            case 34568: return "cn/wow";        // Wownero
            case 38081: return "cn/half";       // MSR
            case 48782: return "cn/r";          // Lethean
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
        if (m = reXMRig.exec(agent)) {
            const majorv = parseInt(m[1]) * 10000;
            const minorv = parseInt(m[2]) * 100;
            if (majorv + minorv < 21300) {
                return "You must update your XMRig miner (" + agent + ") to v2.13.0+";
            }
        } else if (m = reXMRSTAK.exec(agent)) {
            const majorv = parseInt(m[1]) * 10000;
            const minorv = parseInt(m[2]) * 100;
            if (majorv + minorv < 20900) {
                return "You must update your xmr-stak miner (" + agent + ") to v2.9.0+ (and use cryptonight_r in config)";
            }
        } else if (m = reXNP.exec(agent)) {
            const majorv = parseInt(m[1]) * 10000;
            const minorv = parseInt(m[2]) * 100;
            const minorv2 = parseInt(m[3]);
            const version = majorv + minorv + minorv2;
            if (version < 3) {
                return "You must update your xmr-node-proxy (" + agent + ") to version v0.8.1+ (from https://github.com/MoneroOcean/xmr-node-proxy repo)";
            }
            if (version >= 100 && version < 801) {
                return "You must update your xmr-node-proxy (" + agent + ") to version v0.8.1+ (from https://github.com/MoneroOcean/xmr-node-proxy repo)";
            }
        } else if (m = reCAST.exec(agent)) {
            const majorv = parseInt(m[1]) * 10000;
            const minorv = parseInt(m[2]) * 100;
            const minorv2 = parseInt(m[3]);
            if (majorv + minorv + minorv2 <= 10800) {
                 return "Your cast-xmr miner (" + agent + ") is no longer supported (please change miner to xmrig-amd)";
            }
        } else if (m = reSRB.exec(agent)) {
            const majorv = parseInt(m[1]) * 10000;
            const minorv = parseInt(m[2]) * 100;
            const minorv2 = parseInt(m[3]);
            if (majorv + minorv + minorv2 < 10709) {
                 return "You must update your SRBminer (" + agent + ") to version v1.7.9+";
            }
        }
        return false;
    };
    
    this.get_miner_agent_warning_notification = function(agent) {
        let m;
        if (m = reXMRig.exec(agent)) {
            const majorv = parseInt(m[1]) * 10000;
            const minorv = parseInt(m[2]) * 100;
            if (majorv + minorv < 21300) {
                return "Please update your XMRig miner (" + agent + ") to v2.13.0+ to support new cn/r Monero algo before March 9 Monero fork";
            }
        } else if (m = reXMRSTAK2.exec(agent)) {
            const majorv = parseInt(m[1]) * 10000;
            const minorv = parseInt(m[2]) * 100;
            const minorv2 = parseInt(m[3]);
            if (majorv + minorv + minorv2 < 20900) {
                return "Please update your xmr-stak miner (" + agent + ") to v2.9.0+ (and use cryptonight_r in config) to support new cn/r Monero algo before March 9 Monero fork";
            }
        } else if (m = reXNP.exec(agent)) {
            const majorv = parseInt(m[1]) * 10000;
            const minorv = parseInt(m[2]) * 100;
            const minorv2 = parseInt(m[3]);
            const version = majorv + minorv + minorv2;
            if (version < 801) {
                 return "Please update your xmr-node-proxy (" + agent + ") to version v0.8.1+ by doing 'cd xmr-node-proxy && ./update.sh' (or check https://github.com/MoneroOcean/xmr-node-proxy repo) to support new cn/r Monero algo before March 9 Monero fork";
            }
        } else if (m = reSRB.exec(agent)) {
            const majorv = parseInt(m[1]) * 10000;
            const minorv = parseInt(m[2]) * 100;
            const minorv2 = parseInt(m[3]);
            if (majorv + minorv + minorv2 < 10709) {
                 return "Please update your SRBminer (" + agent + ") to version v1.7.9+ to support new cn/r Monero algo before March 9 Monero fork";
            }
        }
        return false;
    };

};



module.exports = Coin;
