(function () {
    "use strict";

    function isIp(value) {
        if (!value) {
            return false;
        }

        const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value);
        if (ipv4) {
            return value.split(".").every(part => Number(part) <= 255);
        }

        if (!value.includes(":")) {
            return false;
        }

        const runs = value.split("::");
        if (runs.length > 2) {
            return false;
        }

        const groups = value.split(":").filter(group => group.length > 0);
        if (groups.length > 8 || (runs.length === 1 && groups.length !== 8)) {
            return false;
        }

        return groups.every(group => /^[0-9a-f]{1,4}$/i.test(group));
    }

    function addressOf(candidate) {
        if (candidate && candidate.address) {
            return candidate.address;
        }

        const parts = String(candidate && candidate.candidate || "").split(" ");
        return parts.length > 4 ? parts[4] : "";
    }

    function addressFamily(address) {
        if (address && address.includes(":")) {
            return "IPv6";
        }

        if (isIp(address)) {
            return "IPv4";
        }

        return "mDNS";
    }

    function classifyAddress(address) {
        if (!address) {
            return "unknown";
        }

        if (/\.local$/i.test(address)) {
            return "mdns";
        }

        if (address === "127.0.0.1" ||
            address === "::1") {
            return "loopback";
        }

        if (/^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.)/i.test(address) ||
            /^(fc|fd|fe80:)/i.test(address)) {
            return "local";
        }

        return isIp(address) ? "public" : "unknown";
    }

    function detectWebRtcLeak(options) {
        const opts = options || {};
        const timeoutMs = opts.timeoutMs || 4000;
        const stunUrls = opts.stunUrls || ["stun:stun.l.google.com:19302"];

        return new Promise(resolve => {
            if (typeof window === "undefined") {
                resolve({
                    supported: false,
                    complete: false,
                    status: "unsupported",
                    ips: [],
                    candidates: [],
                    errors: [],
                    detail: "没有浏览器窗口环境"
                });
                return;
            }

            const Rtc = window.RTCPeerConnection || window.webkitRTCPeerConnection;
            if (!Rtc) {
                resolve({
                    supported: false,
                    complete: false,
                    status: "unsupported",
                    ips: [],
                    candidates: [],
                    errors: [],
                    detail: "WebView2 没有提供 RTCPeerConnection"
                });
                return;
            }

            let peerConnection;
            try {
                peerConnection = new Rtc({
                    iceServers: [{ urls: stunUrls }]
                });
            } catch (error) {
                resolve({
                    supported: false,
                    complete: false,
                    status: "error",
                    ips: [],
                    candidates: [],
                    errors: [],
                    detail: "创建 RTCPeerConnection 失败",
                    error: String(error)
                });
                return;
            }

            const ips = new Set();
            const candidates = [];
            const errors = [];
            let finished = false;
            const timer = setTimeout(() => finish("incomplete"), timeoutMs);

            function finish(status, error) {
                if (finished) {
                    return;
                }

                finished = true;
                clearTimeout(timer);
                try {
                    peerConnection.close();
                } catch (_) {
                }

                resolve({
                    supported: status !== "error",
                    complete: status === "complete",
                    status,
                    ips: Array.from(ips),
                    candidates,
                    errors,
                    detail: status === "complete"
                        ? "ICE 候选收集完成"
                        : status === "incomplete"
                            ? "ICE 候选收集在超时前未完成"
                            : "ICE 候选收集失败",
                    error: error ? String(error) : ""
                });
            }

            try {
                peerConnection.createDataChannel("guardian-probe");
            } catch (error) {
                finish("error", error);
                return;
            }

            peerConnection.onicecandidate = event => {
                if (!event.candidate) {
                    finish("complete");
                    return;
                }

                const address = addressOf(event.candidate);
                if (!address) {
                    return;
                }

                const kind = classifyAddress(address);
                candidates.push({
                    address,
                    kind,
                    addressFamily: addressFamily(address)
                });

                if (isIp(address)) {
                    ips.add(address);
                }
            };

            peerConnection.onicecandidateerror = event => {
                errors.push({
                    url: event.url || "",
                    code: Number(event.errorCode || 0),
                    text: event.errorText || ""
                });
            };

            peerConnection.createOffer()
                .then(offer => peerConnection.setLocalDescription(offer))
                .catch(error => finish("error", error));
        });
    }

    window.guardianDetectWebRtcLeak = detectWebRtcLeak;
})();
