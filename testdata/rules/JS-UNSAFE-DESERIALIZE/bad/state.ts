// ruleid: JS-UNSAFE-DESERIALIZE
import serialize from "serialize-to-js";

export const restore = (text: string) => serialize.deserialize(text);
