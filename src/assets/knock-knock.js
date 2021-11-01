"use strict";
var SignInState;
(function (SignInState) {
    SignInState[SignInState["Username"] = 0] = "Username";
    SignInState[SignInState["ChallengeResponse"] = 1] = "ChallengeResponse";
    SignInState[SignInState["Success"] = 2] = "Success";
    SignInState[SignInState["Failure"] = 3] = "Failure";
})(SignInState || (SignInState = {}));
class SignInManager {
    constructor(currentState = SignInState.Username) {
        this.currentState = currentState;
        this.scriptTag = document.scripts[document.scripts.length - 1];
        this.parentTag = this.scriptTag.parentNode;
        this.formTag = this.findParentNode(this.scriptTag, (tag) => tag instanceof HTMLFormElement);
        this.challengeDelegate = (() => {
            if (!this.scriptTag.hasAttribute("kk-delegate")) {
                return () => { };
            }
            const delegate = this.scriptTag.getAttribute("kk-delegate") ?? "";
            if (typeof (window[delegate]) === "function") {
                return window[delegate].bind(this);
            }
        })();
        document.onreadystatechange = () => {
            if (document.readyState === "complete") {
                this.currentState = SignInState.Username;
                this.mount();
            }
        };
    }
    findParentNode(tag, predicate) {
        if (predicate(tag)) {
            return tag;
        }
        if (tag.parentNode != null) {
            return this.findParentNode(tag.parentNode, predicate);
        }
        return null;
    }
    findChildNode(tag, predicate) {
        if (predicate(tag)) {
            return tag;
        }
        if (tag.hasChildNodes()) {
            let found = null;
            tag.childNodes.forEach((child) => {
                if (found) {
                    return;
                }
                const validChild = this.findChildNode(child, predicate);
                if (validChild) {
                    found = validChild;
                }
            });
            return found;
        }
        return null;
    }
    handleSubmit(evt) {
        evt.preventDefault();
        if (this.formTag != null) {
            const body = new FormData(this.formTag);
            this.doChallenge(body).then(resp => {
                console.log("Done:", resp);
                if (resp && resp.type === "Success") {
                    window.location = resp.redirect;
                    return;
                }
            });
        }
        return false;
    }
    async doChallenge(body) {
        let response = await fetch('/sign-in', {
            method: 'POST',
            body,
        });
        return response.json()
            .then(redirect => {
            console.log("Response:", redirect);
            return {
                type: "Success",
                redirect,
            };
        })
            .catch(() => {
        });
    }
    mount() {
        const button = document.createElement("button");
        button.setAttribute("class", this.scriptTag.getAttribute("kk-class") || "");
        button.innerHTML = "Next";
        if (this.formTag) {
            console.log("Hooking into the form");
            const callback = (response) => {
                const r = response();
                console.log("ChallengeResponse:", r);
            };
            this.formTag.onsubmit = this.handleSubmit.bind(this);
        }
        this.parentTag?.appendChild(button);
    }
}
window["knockknock"] = new SignInManager();
