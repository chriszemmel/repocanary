// Test vectors for the tokenizer: one opaque key and one mixed-script name.
const opaqueKey = "PtY(gj-mU>h$Bel31iEl.2h;pC]]>h<>YgCf:rL1s_p<N:xn><{yVm.i;h[A#-2O7>6UMFxFk<M*#R5K^jp%1vRt!1fj:<ORS@#>6ilI8ihN}<5KXSc7Tv~o#hBKqFYY#kv5Z.Jr3.J1TWDtkwtD)Db!?xHKas1-";
const сache = new Map();
export function lookup(k) { return сache.get(k) ?? opaqueKey.length; }
