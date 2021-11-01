interface KnockKnockAuthChallenge {
    type: "Challenge",
    factor: string,
    data?: { [key: string]: any },
}

interface KnockKnockAuthSuccess {
    type: "Success",
    redirect: string,
}

type KnockKnockEventArgs = KnockKnockAuthChallenge | KnockKnockAuthSuccess;

enum SignInState {
    Username,
    ChallengeResponse,
    Success,
    Failure,
}

class SignInManager {
    private scriptTag: HTMLScriptElement;
    private parentTag: Node | null;
    private formTag: HTMLFormElement | null;
    private challengeDelegate: (evt: KnockKnockEventArgs) => any;

    public constructor(
        private currentState: SignInState = SignInState.Username,
    ) {
        this.scriptTag = document.scripts[document.scripts.length - 1];
        this.parentTag = this.scriptTag.parentNode;
        this.formTag = this.findParentNode<HTMLFormElement>(this.scriptTag, (tag) => tag instanceof HTMLFormElement);

        this.challengeDelegate = (() => {
            if (!this.scriptTag.hasAttribute("kk-delegate")) {
                return () => { };
            }

            const delegate = this.scriptTag.getAttribute("kk-delegate") ?? "";
            if (typeof ((window as any)[delegate]) === "function") {
                return (window as any)[delegate].bind(this);
            }
        })();

        document.onreadystatechange = () => {
            if (document.readyState === "complete") {
                this.currentState = SignInState.Username;
                this.mount()
            }
        }
    }

    private findParentNode<T>(tag: Node, predicate: (tag: Node) => boolean): T | null {
        if (predicate(tag)) {
            return tag as unknown as T;
        }

        if (tag.parentNode != null) {
            return this.findParentNode(tag.parentNode, predicate)
        }

        return null;
    }

    private findChildNode<T>(tag: Node, predicate: (tag: Node) => boolean): T | null {
        if (predicate(tag)) {
            return tag as unknown as T;
        }

        if (tag.hasChildNodes()) {
            let found: T | null = null;
            tag.childNodes.forEach((child) => {
                if (found) {
                    return;
                }

                const validChild = this.findChildNode<T>(child, predicate);
                if (validChild) {
                    found = validChild;
                }
            });

            return found;
        }

        return null;
    }

    private handleSubmit(evt: Event) {
        evt.preventDefault();
        if (this.formTag != null) {
            const body = new FormData(this.formTag);
            this.doChallenge(body).then(resp => {
                console.log("Done:", resp)

                if (resp && resp.type === "Success") {
                    window.location = resp.redirect as any;
                    return;
                }
            })
        }

        return false;
    }

    private async doChallenge(body: FormData): Promise<void | KnockKnockEventArgs> {
        let response = await fetch('/sign-in', {
            method: 'POST',
            body,
        });

        return response.json()
            .then(redirect => {
                console.log("Response:", redirect)

                return {
                    type: "Success",
                    redirect,
                } as KnockKnockAuthSuccess
            })
            .catch(() => {

            })
    }

    private mount() {
        const button = document.createElement("button")
        button.setAttribute("class", this.scriptTag.getAttribute("kk-class") || "")
        button.innerHTML = "Next"

        if (this.formTag) {
            console.log("Hooking into the form")

            const callback = (response: () => any) => {
                const r = response()
                console.log("ChallengeResponse:", r)
            };

            this.formTag.onsubmit = this.handleSubmit.bind(this);
        }

        this.parentTag?.appendChild(button)
    }

}

(window as any)["knockknock"] = new SignInManager();

