import Common from "./Common";

export default class AmtRedirect {
    constructor(props) {
        this.m = props.module;
        this.m.parent = this;
        this.State = 0;
        this.socket = null;
        this.host = null;
        this.port = 0;
        this.user = null;
        this.pass = null;
        this.authuri = "/RedirectionService";
        this.tlsv1only = 0;
        this.inDataCount = 0;
        this.connectstate = 0;
        this.protocol = this.m.protocol;
        this.debugmode = 0;

        this.amtaccumulator = "";
        this.amtsequence = 1;
        this.amtkeepalivetimer = null;
        this.onStateChanged = null;
        this.RedirectStartSol = String.fromCharCode(0x10, 0x00, 0x00, 0x00, 0x53, 0x4F, 0x4C, 0x20);
        this.RedirectStartKvm = String.fromCharCode(0x10, 0x01, 0x00, 0x00, 0x4b, 0x56, 0x4d, 0x52);
        this.RedirectStartIder = String.fromCharCode(0x10, 0x00, 0x00, 0x00, 0x49, 0x44, 0x45, 0x52);
        this.xxRandomNonceX = "abcdef0123456789";
        this.common = new Common();
    }
    Start(host, port, user, pass, tls){
        this.host = host;
        this.port = port;
        this.user = user;
        this.connectstate = 0;
        this.inDataCount = 0;
        this.socket = new WebSocket(window.location.protocol.replace("http", "ws") + "//" + window.location.host + window.location.pathname.substring(0, window.location.pathname.lastIndexOf('/')) + "/webrelay.ashx?p=2&host=" + host + "&port=" + port + "&tls=" + tls + ((user == '*') ? "&serverauth=1" : "") + ((typeof pass === "undefined") ? ("&serverauth=1&user=" + user) : ""));
        
        this.socket.onopen = this.xxOnSocketConnected.bind(this);
        this.socket.onmessage = this.xxOnMessage.bind(this);
        this.socket.onclose = this.xxOnSocketClosed.bind(this);
        this.xxStateChange(1);
    }
    xxOnSocketConnected() {
        if (this.debugmode == 1) { console.log('onSocketConnected'); }
        this.xxStateChange(2);
        if (this.protocol == 1) this.xxSend(this.RedirectStartSol); // TODO: Put these strings in higher level module to tighten code
        if (this.protocol == 2) this.xxSend(this.RedirectStartKvm); // Don't need these is the feature is not compiled-in.
        if (this.protocol == 3) this.xxSend(this.RedirectStartIder);
    }
    xxOnMessage(e) {
        if (this.debugmode == 1) { console.log('Recv', e.data); }
        this.inDataCount++;
        if (typeof e.data == 'object') {
            var f = new FileReader();
            if (f.readAsBinaryString) {
                // Chrome & Firefox (Draft)
                f.onload = function (e) { this.xxOnSocketData(e.target.result); }
                f.readAsBinaryString(new Blob([e.data]));
            } else if (f.readAsArrayBuffer) {
                // Chrome & Firefox (Spec)
                f.onloadend = function (e) { this.xxOnSocketData(e.target.result); }
                f.readAsArrayBuffer(e.data);
            } else {
                // IE10, readAsBinaryString does not exist, use an alternative.
                var binary = "";
                var bytes = new Uint8Array(e.data);
                var length = bytes.byteLength;
                for (var i = 0; i < length; i++) { binary += String.fromCharCode(bytes[i]); }
                this.xxOnSocketData(binary);
            }
        } else {
            // If we get a string object, it maybe the WebRTC confirm. Ignore it.
            // this.debug("MeshDataChannel - OnData - " + typeof e.data + " - " + e.data.length);
            this.xxOnSocketData(e.data);
        }
    }

    xxOnSocketData(data) {
        if (!data || this.connectstate == -1) return;

        if (typeof data === 'object') {
            // This is an ArrayBuffer, convert it to a string array (used in IE)
            var binary = "";
            var bytes = new Uint8Array(data);
            var length = bytes.byteLength;
            for (var i = 0; i < length; i++) { binary += String.fromCharCode(bytes[i]); }
            data = binary;
        }
        else if (typeof data !== 'string') { return; }

        if ((this.protocol == 2 || this.protocol == 3) && this.connectstate == 1) { return this.m.ProcessData(data); } // KVM traffic, forward it directly.
        this.amtaccumulator += data;
        //this.Debug("Redir Recv(" + this.amtaccumulator.length + "): " + rstr2hex(this.amtaccumulator));
        while (this.amtaccumulator.length >= 1) {
            var cmdsize = 0;
            switch (this.amtaccumulator.charCodeAt(0)) {
                case 0x11: // StartRedirectionSessionReply (17)
                    if (this.amtaccumulator.length < 4) return;
                    var statuscode = this.amtaccumulator.charCodeAt(1);
                    switch (statuscode) {
                        case 0: // STATUS_SUCCESS
                            if (this.amtaccumulator.length < 13) return;
                            var oemlen = this.amtaccumulator.charCodeAt(12);
                            if (this.amtaccumulator.length < 13 + oemlen) return;
                            // Query for available authentication
                            this.xxSend(String.fromCharCode(0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)); // Query authentication support
                            cmdsize = (13 + oemlen);
                            break;
                        default:
                            this.Stop(1);
                            break;
                    }
                    break;
                case 0x14: // AuthenticateSessionReply (20)
                    if (this.amtaccumulator.length < 9) return;
                    var authDataLen = ReadIntX(this.amtaccumulator, 5);
                    if (this.amtaccumulator.length < 9 + authDataLen) return;
                    var status = this.amtaccumulator.charCodeAt(1);
                    var authType = this.amtaccumulator.charCodeAt(4);
                    var authData = [];
                    for (i = 0; i < authDataLen; i++) { authData.push(this.amtaccumulator.charCodeAt(9 + i)); }
                    var authDataBuf = this.amtaccumulator.substring(9, 9 + authDataLen);
                    cmdsize = 9 + authDataLen;
                    if (authType == 0) {
                        // Query
                        if (authData.indexOf(4) >= 0) {
                            // Good Digest Auth (With cnonce and all)
                            this.xxSend(String.fromCharCode(0x13, 0x00, 0x00, 0x00, 0x04) + this.common.IntToStrX(this.user.length + this.authuri.length + 8) + String.fromCharCode(this.user.length) + this.user + String.fromCharCode(0x00, 0x00) + String.fromCharCode(this.authuri.length) + this.authuri + String.fromCharCode(0x00, 0x00, 0x00, 0x00));
                        }
                        else if (authData.indexOf(3) >= 0) {
                            // Bad Digest Auth (Not sure why this is supported, cnonce is not used!)
                            this.xxSend(String.fromCharCode(0x13, 0x00, 0x00, 0x00, 0x03) + this.common.IntToStrX(this.user.length + this.authuri.length + 7) + String.fromCharCode(this.user.length) + this.user + String.fromCharCode(0x00, 0x00) + String.fromCharCode(this.authuri.length) + this.authuri + String.fromCharCode(0x00, 0x00, 0x00));
                        }
                        else if (authData.indexOf(1) >= 0) {
                            // Basic Auth (Probably a good idea to not support this unless this is an old version of Intel AMT)
                            this.xxSend(String.fromCharCode(0x13, 0x00, 0x00, 0x00, 0x01) + this.common.IntToStrX(this.user.length + this.pass.length + 2) + String.fromCharCode(this.user.length) + this.user + String.fromCharCode(this.pass.length) + this.pass);
                        }
                        else this.Stop(2);
                    }
                    else if ((authType == 3 || authType == 4) && status == 1) {
                        var curptr = 0;

                        // Realm
                        var realmlen = authDataBuf.charCodeAt(curptr);
                        var realm = authDataBuf.substring(curptr + 1, curptr + 1 + realmlen);
                        curptr += (realmlen + 1);

                        // Nonce
                        var noncelen = authDataBuf.charCodeAt(curptr);
                        var nonce = authDataBuf.substring(curptr + 1, curptr + 1 + noncelen);
                        curptr += (noncelen + 1);

                        // QOP
                        var qoplen = 0;
                        var qop = null;
                        var cnonce = this.xxRandomNonce(32);
                        var snc = '00000002';
                        var extra = '';
                        if (authType == 4) {
                            qoplen = authDataBuf.charCodeAt(curptr);
                            qop = authDataBuf.substring(curptr + 1, curptr + 1 + qoplen);
                            curptr += (qoplen + 1);
                            extra = snc + ":" + cnonce + ":" + qop + ":";
                        }

                        var digest = hex_md5(hex_md5(this.user + ":" + realm + ":" + this.pass) + ":" + nonce + ":" + extra + hex_md5("POST:" + this.authuri));
                        var totallen = this.user.length + realm.length + nonce.length + this.authuri.length + cnonce.length + snc.length + digest.length + 7;
                        if (authType == 4) totallen += (qop.length + 1);
                        var buf = String.fromCharCode(0x13, 0x00, 0x00, 0x00, authType) + this.common.IntToStrX(totallen) + String.fromCharCode(this.user.length) + this.user + String.fromCharCode(realm.length) + realm + String.fromCharCode(nonce.length) + nonce + String.fromCharCode(this.authuri.length) + this.authuri + String.fromCharCode(cnonce.length) + cnonce + String.fromCharCode(snc.length) + snc + String.fromCharCode(digest.length) + digest;
                        if (authType == 4) buf += (String.fromCharCode(qop.length) + qop);
                        this.xxSend(buf);
                    }
                    else
                    if (status == 0) { // Success
                        if (this.protocol == 1) {
                            // Serial-over-LAN: Send Intel AMT serial settings...
                            var MaxTxBuffer = 10000;
                            var TxTimeout = 100;
                            var TxOverflowTimeout = 0;
                            var RxTimeout = 10000;
                            var RxFlushTimeout = 100;
                            var Heartbeat = 0;//5000;
                            this.xxSend(String.fromCharCode(0x20, 0x00, 0x00, 0x00) + this.common.IntToStrX(this.amtsequence++) + this.common.ShortToStrX(MaxTxBuffer) + this.common.ShortToStrX(TxTimeout) + this.common.ShortToStrX(TxOverflowTimeout) + this.common.ShortToStrX(RxTimeout) + this.common.ShortToStrX(RxFlushTimeout) + this.common.ShortToStrX(Heartbeat) + this.common.IntToStrX(0));
                        }
                        if (this.protocol == 2) {
                            // Remote Desktop: Send traffic directly...
                            this.xxSend(String.fromCharCode(0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00));
                        }
                        if (this.protocol == 3) {
                            // Remote IDER: Send traffic directly...
                            this.connectstate = 1;
                            this.xxStateChange(3);
                        }
                    } else this.Stop(3);
                    break;
                case 0x21: // Response to settings (33)
                    if (this.amtaccumulator.length < 23) break;
                    cmdsize = 23;
                    this.xxSend(String.fromCharCode(0x27, 0x00, 0x00, 0x00) + this.common.IntToStrX(this.amtsequence++) + String.fromCharCode(0x00, 0x00, 0x1B, 0x00, 0x00, 0x00));
                    if (this.protocol == 1) { this.amtkeepalivetimer = setInterval(this.xxSendAmtKeepAlive, 2000); }
                    this.connectstate = 1;
                    this.xxStateChange(3);
                    break;
                case 0x29: // Serial Settings (41)
                    if (this.amtaccumulator.length < 10) break;
                    cmdsize = 10;
                    break;
                case 0x2A: // Incoming display data (42)
                    if (this.amtaccumulator.length < 10) break;
                    var cs = (10 + ((this.amtaccumulator.charCodeAt(9) & 0xFF) << 8) + (this.amtaccumulator.charCodeAt(8) & 0xFF));
                    if (this.amtaccumulator.length < cs) break;
                    this.m.ProcessData(this.amtaccumulator.substring(10, cs));
                    cmdsize = cs;
                    break;
                case 0x2B: // Keep alive message (43)
                    if (this.amtaccumulator.length < 8) break;
                    cmdsize = 8;
                    break;
                case 0x41:
                    if (this.amtaccumulator.length < 8) break;
                    this.connectstate = 1;
                    this.m.Start();
                    // KVM traffic, forward rest of accumulator directly.
                    if (this.amtaccumulator.length > 8) { this.m.ProcessData(this.amtaccumulator.substring(8)); }
                    cmdsize = this.amtaccumulator.length;
                    break;
                default:
                    console.log("Unknown Intel AMT command: " + this.amtaccumulator.charCodeAt(0) + " acclen=" + this.amtaccumulator.length);
                    this.Stop(4);
                    return;
            }
            if (cmdsize == 0) return;
            this.amtaccumulator = this.amtaccumulator.substring(cmdsize);
        }
    }

    xxSend(x) {
        //this.Debug("Redir Send(" + x.length + "): " + rstr2hex(x));
        if (this.socket != null && this.socket.readyState == WebSocket.OPEN) {
            if (this.debugmode == 1) { console.log('Send', x); }
            var b = new Uint8Array(x.length);
            for (var i = 0; i < x.length; ++i) { b[i] = x.charCodeAt(i); }
            this.socket.send(b.buffer);
        }
    }

    send(x) {
        if (this.socket == null || this.connectstate != 1) return;
        if (this.protocol == 1) { this.xxSend(String.fromCharCode(0x28, 0x00, 0x00, 0x00) + this.common.IntToStrX(this.amtsequence++) + this.common.ShortToStrX(x.length) + x); } else { this.xxSend(x); }
    }

    xxSendAmtKeepAlive() {
        if (this.socket == null) return;
        this.xxSend(String.fromCharCode(0x2B, 0x00, 0x00, 0x00) + this.common.IntToStrX(this.amtsequence++));
    }

    xxRandomNonce(length) {
        var r = "";
        for (var i = 0; i < length; i++) { r += this.xxRandomNonceX.charAt(Math.floor(Math.random() * this.xxRandomNonceX.length)); }
        return r;
    }

    xxOnSocketClosed() {
        if (this.debugmode == 1) { console.log('onSocketClosed'); }
        //this.Debug("Redir Socket Closed");
        if ((this.inDataCount == 0) && (this.tlsv1only == 0)) {
            this.tlsv1only = 1;
            this.socket = new WebSocket(window.location.protocol.replace("http", "ws") + "//" + window.location.host + window.location.pathname.substring(0, window.location.pathname.lastIndexOf('/')) + "/webrelay.ashx?p=2&host=" + this.host + "&port=" + this.port + "&tls=" + this.tls + "&tls1only=1" + ((this.user == '*') ? "&serverauth=1" : "") + ((typeof pass === "undefined") ? ("&serverauth=1&user=" + this.user) : "")); // The "p=2" indicates to the relay that this is a REDIRECTION session
            this.socket.onopen = this.xxOnSocketConnected;
            this.socket.onmessage = this.xxOnMessage;
            this.socket.onclose = this.xxOnSocketClosed;
        } else {
            this.Stop(5);
        }
    }

    xxStateChange(newstate) {
        if (this.State == newstate) return;
        this.State = newstate;
        this.m.xxStateChange(this.State);
        if (this.onStateChanged != null) this.onStateChanged(this, this.State);
    }

    Stop(x) {
        if (this.debugmode == 1) { console.log('onSocketStop', x); }
        //this.Debug("Redir Socket Stopped");
        this.xxStateChange(0);
        this.connectstate = -1;
        this.amtaccumulator = "";
        if (this.socket != null) { this.socket.close(); this.socket = null; }
        if (this.amtkeepalivetimer != null) { clearInterval(this.amtkeepalivetimer); this.amtkeepalivetimer = null; }
    }
};
