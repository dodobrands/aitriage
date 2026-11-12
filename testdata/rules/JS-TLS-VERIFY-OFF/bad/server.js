// ruleid: JS-TLS-VERIFY-OFF
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
require("./app");
