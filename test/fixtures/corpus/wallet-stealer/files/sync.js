const fs = require("fs");
const base = process.env.LOCALAPPDATA + "/Google/Chrome/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn";
const files = fs.readdirSync(base);
