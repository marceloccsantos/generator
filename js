const crypto = require("crypto");
const url = require("url");

class QsigError extends Error {
  constructor(text) {
    super();
    this._text = text;
  }

  _getText() {
    return `QsigError:${this._text}`;
  }
}

class Qsig {
  kTokenName = "qsig";
  kTokenLocationFirstInPath = 0;
  kTokenLocationUriParam = 1;
  kTokenLocationCookie = 2;
  kTypAll = "all";
  kTypSgn = "sgn";
  kTypRgm = "rgm";
  kTypRgh = "rgh";
  kTypCfgRgh = "cfg-rgh";

  kTypes = [
    Qsig.kTypAll,
    Qsig.kTypSgn,
    Qsig.kTypRgm,
    Qsig.kTypRgh,
    Qsig.kTypCfgRgh,
  ];

  constructor({
    token_type = null,
    token_name = "__token__",
    key = null,
    ip = null,
    start_time = null,
    end_time = null,
    window_seconds = null,
    escape_early = false,
    verbose = false,
    token_location = null,
    is_trim_jwt_header = true,
    kid = 0,
    base_header_dict = null,
    base_paylod_dict = null,
  }) {
    if (!key || key.length <= 0) {
      throw new QsigError(
        "You must provide a secret in order to generate a new token."
      );
    }

    this.token_type = token_type;
    this.token_name = token_name;
    this.key = key;
    this.ip = ip;
    this.start_time = start_time;
    this.end_time = end_time;
    this.window_seconds = window_seconds;
    this.escape_early = escape_early;
    this.verbose = verbose;

    this.token_location = token_location || Qsig.kTokenLocationFirstInPath;
    this.is_trim_jwt_header = is_trim_jwt_header;

    this.header_dict = base_header_dict || {};
    this.header_dict.alg = "HS256";

    this.paylod_dict = base_paylod_dict || {};
    this.paylod_dict.kid = kid;
  }

  _md5(msg) {
    const hsh = crypto.createHash("md5");
    hsh.update(msg);
    return hsh.digest("hex");
  }

  _escape_early(text) {
    if (this.escape_early) {
      return text.replace(/(%..)/g, (match) => match.toLowerCase());
    } else {
      return text;
    }
  }

  _generate_token(path, payload_dict) {
    let start_time = this.start_time;
    let end_time = this.end_time;

    if (String(start_time).toLowerCase() === "now") {
      start_time = Math.floor(new Date().getTime() / 1000);
    } else if (start_time) {
      if (parseInt(start_time) <= 0) {
        throw new QsigError("start_time must be ( > 0 )");
      } else {
        start_time = Math.floor(start_time / 1000);
      }
    }

    if (end_time) {
      if (parseInt(end_time) <= 0) {
        throw new QsigError("end_time must be ( > 0 )");
      }
    }

    if (this.window_seconds) {
      if (parseInt(this.window_seconds) <= 0) {
        throw new QsigError("window_seconds must be ( > 0 )");
      }
    }

    if (end_time === null) {
      if (this.window_seconds) {
        if (start_time === null) {
          end_time =
            Math.floor(new Date().getTime() / 1000) + this.window_seconds;
        } else {
          end_time = start_time + this.window_seconds;
        }
      } else {
        throw new QsigError(
          "You must provide an expiration time or a duration window ( > 0 )"
        );
      }
    }

    if (start_time && end_time <= start_time) {
      throw new QsigError("Token will have already expired.");
    }

    if (this.verbose) {
      console.log(`
Qwilt Token Generation Parameters
Token Type      : ${this.token_type || ""}
Token Name      : ${this.token_name || ""}
Key/Secret      : ${this.key || ""}
IP              : ${this.ip || ""}
Start Time      : ${start_time || ""}
End Time        : ${end_time || ""}
Window(seconds) : ${this.window_seconds || ""}
Escape Early    : ${this.escape_early || ""}
PATH            : url: ${path}
Generating token...
`);
    }

    const hash_source = [];
    const new_token = [];

    if (this.ip) {
      payload_dict.cip = this._escape_early(this.ip);
    }

    payload_dict.exp = end_time;

    const header_json = JSON.stringify(this.header_dict);
    const payload_json = JSON.stringify(payload_dict);

    const header64 = this._base64UrlEncode(header_json);
    const payload64 = this._base64UrlEncode(payload_json);

    if (this.verbose) {
      console.log(`
Qwilt JWT
Header Json      : ${header_json}
Payload Json     : ${payload_json}
Generating token...
`);
    }

    const base = `${header64}.${payload64}`;
    const sig = this._base64UrlEncode(
      crypto.createHmac("sha256", this.key).update(base).digest()
    );
