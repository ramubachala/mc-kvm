/** 
* @description WSMAN communication using websocket
* @author Ylian Saint-Hilaire, Ramu Bachala
* @version v0.2.0c
*/
export default class WsmanComm {
    constructor(params) {
        this.PendingAjax = [];               // List of pending AJAX calls. When one frees up, another will start.
        this.ActiveAjaxCount = 0;            // Number of currently active AJAX calls
        this.MaxActiveAjaxCount = 1;         // Maximum number of activate AJAX calls at the same time.
        this.FailAllError = 0;               // Set this to non-zero to fail all AJAX calls with that error status, 999 causes responses to be silent.
        this.challengeParams = null;
        this.noncecounter = 1;
        this.authcounter = 0;
        this.socket = null;
        this.socketState = 0;
        this.host = params.host;
        this.port = params.port;
        this.user = params.user;
        this.pass = params.pass;
        this.tls = params.tls;
        this.tlsv1only = 1;
        this.cnonce = Math.random().toString(36).substring(7); // Generate a random client nonce
    
    
        this.pendingAjaxCall = [];
    }

    PerformAjax(postdata, callback, tag, pri, url, action){
        if (this.ActiveAjaxCount < this.MaxActiveAjaxCount && this.PendingAjax.length == 0) {
            // There are no pending AJAX calls, perform the call now.
            this.PerformAjaxEx(postdata, callback, tag, url, action);
        } else {
            // If this is a high priority call, put this call in front of the array, otherwise put it in the back.
            if (pri == 1) { this.PendingAjax.unshift([postdata, callback, tag, url, action]); } else { this.PendingAjax.push([postdata, callback, tag, url, action]); }
        }
    }

    PerformNextAjax() {
        if (this.ActiveAjaxCount >= this.MaxActiveAjaxCount || this.PendingAjax.length == 0) return;
        var x = this.PendingAjax.shift();
        this.PerformAjaxEx(x[0], x[1], x[2], x[3], x[4]);
        this.PerformNextAjax();
    }

    PerformAjaxEx(postdata, callback, tag, url, action) {
        if (this.FailAllError != 0) { this.gotNextMessagesError({ status: this.FailAllError }, 'error', null, [postdata, callback, tag, url, action]); return; }
        if (!postdata) postdata = "";
        //console.log("SEND: " + postdata); // DEBUG

        // We are in a websocket relay environment 
        this.ActiveAjaxCount++;
        return this.PerformAjaxExNodeJS(postdata, callback, tag, url, action);
    }


    PerformAjaxExNodeJS(postdata, callback, tag, url, action) { this.PerformAjaxExNodeJS2(postdata, callback, tag, url, action, 3); }

    PerformAjaxExNodeJS2(postdata, callback, tag, url, action, retry) {
        if (retry <= 0 || this.FailAllError != 0) {
            // Too many retry, fail here.
            this.ActiveAjaxCount--;
            if (this.FailAllError != 999) this.gotNextMessages(null, 'error', { status: ((this.FailAllError == 0) ? 408 : this.FailAllError) }, [postdata, callback, tag, url, action]); // 408 is timeout error
            this.PerformNextAjax();
            return;
        }
        this.pendingAjaxCall.push([postdata, callback, tag, url, action, retry]);
        if (this.socketState == 0) { this.xxConnectHttpSocket(); }
        else if (this.socketState == 2) { this.sendRequest(postdata, url, action); }
    }

    sendRequest(postdata, url, action) {
        url = url ? url : "/wsman";
        action = action ? action : "POST";
        var h = action + " " + url + " HTTP/1.1\r\n";
        if (this.challengeParams != null) {
            var response = hex_md5(hex_md5(this.user + ':' + this.challengeParams["realm"] + ':' + this.pass) + ':' + this.challengeParams["nonce"] + ':' + this.noncecounter + ':' + this.cnonce + ':' + this.challengeParams["qop"] + ':' + hex_md5(action + ':' + url));
            h += 'Authorization: ' + this.renderDigest({ "username": this.user, "realm": this.challengeParams["realm"], "nonce": this.challengeParams["nonce"], "uri": url, "qop": this.challengeParams["qop"], "response": response, "nc": this.noncecounter++, "cnonce": this.cnonce }) + '\r\n';
        }
        //h += 'Host: ' + obj.host + ':' + obj.port + '\r\nContent-Length: ' + postdata.length + '\r\n\r\n' + postdata; // Use Content-Length
        h += 'Host: ' + this.host + ':' + this.port + '\r\nTransfer-Encoding: chunked\r\n\r\n' + postdata.length.toString(16).toUpperCase() + '\r\n' + postdata + '\r\n0\r\n\r\n'; // Use Chunked-Encoding
        this._Send(h);
        //obj.Debug("SEND: " + h); // Display send packet
    }

    parseDigest(header) {
        var t = header.substring(7).split(',');
        for (i in t) t[i] = t[i].trim();
        return t.reduce(function (obj, s) { var parts = s.split('='); obj[parts[0]] = parts[1].replace(/"/g, ''); return obj; }, {})
    }

    renderDigest(params) {
        var paramsnames = [];
        for (i in params) { paramsnames.push(i); }
        return 'Digest ' + paramsnames.reduce(function (s1, ii) { return s1 + ',' + ii + '="' + params[ii] + '"' }, '').substring(1);
    }

    xxConnectHttpSocket() {
        //obj.Debug("xxConnectHttpSocket");
        this.socketParseState = 0;
        this.socketAccumulator = '';
        this.socketHeader = null;
        this.socketData = '';
        this.socketState = 1;

        console.log(this.tlsv1only);
        this.socket = new WebSocket(window.location.protocol.replace("http", "ws") + "//" + window.location.host + window.location.pathname.substring(0, window.location.pathname.lastIndexOf('/')) + "/webrelay.ashx?p=1&host=" + this.host + "&port=" + this.port + "&tls=" + this.tls + "&tlsv1only=" + this.tlsv1only + ((user == '*') ? "&serverauth=1" : "") + ((typeof pass === "undefined") ? ("&serverauth=1&user=" + user) : "")); // The "p=1" indicates to the relay that this is a WSMAN session
        this.socket.onopen = this._OnSocketConnected.bind(this);
        this.socket.onmessage = this._OnMessage.bind(this);
        this.socket.onclose = this._OnSocketClosed.bind(this);
    }

    // Websocket relay specific private method
    _OnSocketConnected() {
        //obj.Debug("xxOnSocketConnected");
        this.socketState = 2;
        for (i in this.pendingAjaxCall) { this.sendRequest(obj.pendingAjaxCall[i][0], this.pendingAjaxCall[i][3], this.pendingAjaxCall[i][4]); }
    }

    _OnMessage(e) {
        if (typeof e.data == 'object') {
            var f = new FileReader();
            if (f.readAsBinaryString) {
                // Chrome & Firefox (Draft)
                f.onload = function (e) { _OnSocketData(e.target.result); }
                f.readAsBinaryString(new Blob([e.data]));
            } else if (f.readAsArrayBuffer) {
                // Chrome & Firefox (Spec)
                f.onloadend = function (e) { _OnSocketData(e.target.result); }
                f.readAsArrayBuffer(e.data);
            } else {
                // IE10, readAsBinaryString does not exist, use an alternative.
                var binary = "";
                var bytes = new Uint8Array(e.data);
                var length = bytes.byteLength;
                for (var i = 0; i < length; i++) { binary += String.fromCharCode(bytes[i]); }
                this._OnSocketData(binary);
            }
        } else if (typeof e.data == 'string') {
            // We got a string object
            this._OnSocketData(e.data);
        }
    };

    // Websocket relay specific private method
    _OnSocketData(data) {
        //obj.Debug("_OnSocketData (" + data.length + "): " + data);

        if (typeof data === 'object') {
            // This is an ArrayBuffer, convert it to a string array (used in IE)
            var binary = "", bytes = new Uint8Array(data), length = bytes.byteLength;
            for (var i = 0; i < length; i++) { binary += String.fromCharCode(bytes[i]); }
            data = binary;
        }
        else if (typeof data !== 'string') return;

        //console.log("RECV: " + data); // DEBUG

        this.socketAccumulator += data;
        while (true) {
            if (this.socketParseState == 0) {
                var headersize = this.socketAccumulator.indexOf("\r\n\r\n");
                if (headersize < 0) return;
                //obj.Debug(obj.socketAccumulator.substring(0, headersize)); // Display received HTTP header
                this.socketHeader = this.socketAccumulator.substring(0, headersize).split("\r\n");
                this.socketAccumulator = this.socketAccumulator.substring(headersize + 4);
                this.socketParseState = 1;
                this.socketData = '';
                this.socketXHeader = { Directive: this.socketHeader[0].split(' ') };
                for (i in this.socketHeader) {
                    if (i != 0) {
                        var x2 = this.socketHeader[i].indexOf(':');
                        this.socketXHeader[this.socketHeader[i].substring(0, x2).toLowerCase()] = this.socketHeader[i].substring(x2 + 2);
                    }
                }
            }
            if (this.socketParseState == 1) {
                var csize = -1;
                if ((this.socketXHeader["connection"] != undefined) && (this.socketXHeader["connection"].toLowerCase() == 'close') && ((this.socketXHeader["transfer-encoding"] == undefined) || (this.socketXHeader["transfer-encoding"].toLowerCase() != 'chunked'))) {
                    // The body ends with a close, in this case, we will only process the header
                    csize = 0;
                } else if (this.socketXHeader["content-length"] != undefined) {
                    // The body length is specified by the content-length
                    csize = parseInt(this.socketXHeader["content-length"]);
                    if (this.socketAccumulator.length < csize) return;
                    var data = this.socketAccumulator.substring(0, csize);
                    this.socketAccumulator = this.socketAccumulator.substring(csize);
                    this.socketData = data;
                    csize = 0;
                } else {
                    // The body is chunked
                    var clen = this.socketAccumulator.indexOf("\r\n");
                    if (clen < 0) return; // Chunk length not found, exit now and get more data.
                    // Chunk length if found, lets see if we can get the data.
                    csize = parseInt(this.socketAccumulator.substring(0, clen), 16);
                    if (isNaN(csize)) { if (obj.websocket) { obj.websocket.close(); } return; } // Critical error, close the socket and exit.
                    if (this.socketAccumulator.length < clen + 2 + csize + 2) return;
                    // We got a chunk with all of the data, handle the chunck now.
                    var data = this.socketAccumulator.substring(clen + 2, clen + 2 + csize);
                    this.socketAccumulator = this.socketAccumulator.substring(clen + 2 + csize + 2);
                    this.socketData += data;
                }
                if (csize == 0) {
                    //obj.Debug("_OnSocketData DONE: (" + obj.socketData.length + "): " + obj.socketData);
                    this._ProcessHttpResponse(this.socketXHeader, this.socketData);
                    this.socketParseState = 0;
                    this.socketHeader = null;
                }
            }
        }
    }

    // Websocket relay specific private method
    _ProcessHttpResponse(header, data) {
        //obj.Debug("_ProcessHttpResponse: " + header.Directive[1]);

        var s = parseInt(header.Directive[1]);
        if (isNaN(s)) s = 602;
        if (s == 401 && ++(this.authcounter) < 3) {
            this.challengeParams = this.parseDigest(header['www-authenticate']); // Set the digest parameters, after this, the socket will close and we will auto-retry
        } else {
            var r = this.pendingAjaxCall.shift();
            // if (s != 200) { obj.Debug("Error, status=" + s + "\r\n\r\nreq=" + r[0] + "\r\n\r\nresp=" + data); } // Debug: Display the request & response if something did not work.
            this.authcounter = 0;
            this.ActiveAjaxCount--;
            this.gotNextMessages(data, 'success', { status: s }, r);
            this.PerformNextAjax();
        }
    }

    // Websocket relay specific private method
    _OnSocketClosed(data) {
        //obj.Debug("_OnSocketClosed");
        this.socketState = 0;
        if (this.socket != null) { this.socket.close(); this.socket = null; }
        if (this.pendingAjaxCall.length > 0) {
            var r = this.pendingAjaxCall.shift();
            var retry = r[5];
            this.PerformAjaxExNodeJS2(r[0], r[1], r[2], r[3], r[4], --retry);
        }
    }

    // Websocket relay specific private method
    _Send(x) {
        //console.log("SEND: " + x); // DEBUG
        if (this.socketState == 2 && this.socket != null && this.socket.readyState == WebSocket.OPEN) {
            var b = new Uint8Array(x.length);
            for (var i = 0; i < x.length; ++i) { b[i] = x.charCodeAt(i); }
            try { this.socket.send(b.buffer); } catch (e) { }
        }
    }

    // Private method
    gotNextMessages(data, status, request, callArgs) {
        if (this.FailAllError == 999) return;
        if (this.FailAllError != 0) { callArgs[1](null, this.FailAllError, callArgs[2]); return; }
        if (request.status != 200) { callArgs[1](null, request.status, callArgs[2]); return; }
        callArgs[1](data, 200, callArgs[2]);
    }

    // Private method
    gotNextMessagesError(request, status, errorThrown, callArgs) {
        if (this.FailAllError == 999) return;
        if (this.FailAllError != 0) { callArgs[1](null, this.FailAllError, callArgs[2]); return; }
        callArgs[1](this, null, { Header: { HttpError: request.status } }, request.status, callArgs[2]);
    }

    // Cancel all pending queries with given status
    CancelAllQueries(s) {
        while (this.PendingAjax.length > 0) { var x = this.PendingAjax.shift(); x[1](null, s, x[2]); }
        if (this.websocket != null) { this.websocket.close(); this.websocket = null; this.socketState = 0; }
    }

};


