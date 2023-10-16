import { createParser, CodecMap } from "lumos-experimental-molecule";
import { readFileSync } from "fs";
import { join } from "path";
import { BI, BIish } from "@ckb-lumos/bi";
import {
  createFixedBytesCodec,
  createBytesCodec,
  AnyCodec,
  number as numberCodecs,
  bytes,
} from "@ckb-lumos/codec";
const { Uint32LE } = numberCodecs;
const { bytify } = bytes;

// Copied over from https://github.com/ckb-js/lumos/blob/ed5dc56de240c31b803dcd3cf849a89466f101ed/packages/codec/src/number/uint.ts,
// since lumos codec does not support all the number formats we use.
function assertNumberRange(
  value: BIish,
  min: BIish,
  max: BIish,
  typeName: string,
): void {
  value = BI.from(value);

  if (value.lt(min) || value.gt(max)) {
    throw new Error(
      `Value must be between ${min.toString()} and ${max.toString()}, but got ${value.toString()}`,
    );
  }
}

const createUintBICodec = (byteLength: number, littleEndian = false) => {
  const max = BI.from(1)
    .shl(byteLength * 8)
    .sub(1);

  return createFixedBytesCodec<BI, BIish>({
    byteLength,
    pack(biIsh) {
      let endianType: "LE" | "BE" | "" = littleEndian ? "LE" : "BE";

      if (byteLength <= 1) {
        endianType = "";
      }
      const typeName = `Uint${byteLength * 8}${endianType}`;
      if (typeof biIsh === "number" && !Number.isSafeInteger(biIsh)) {
        throw new Error(`${biIsh} is not a safe integer`);
      }

      let num = BI.from(biIsh);
      assertNumberRange(num, 0, max, typeName);

      const result = new DataView(new ArrayBuffer(byteLength));

      for (let i = 0; i < byteLength; i++) {
        if (littleEndian) {
          result.setUint8(i, num.and(0xff).toNumber());
        } else {
          result.setUint8(byteLength - i - 1, num.and(0xff).toNumber());
        }
        num = num.shr(8);
      }

      return new Uint8Array(result.buffer);
    },
    unpack: (buf) => {
      const view = new DataView(Uint8Array.from(buf).buffer);
      let result = BI.from(0);

      for (let i = 0; i < byteLength; i++) {
        if (littleEndian) {
          result = result.or(BI.from(view.getUint8(i)).shl(i * 8));
        } else {
          result = result.shl(8).or(view.getUint8(i));
        }
      }

      return result;
    },
  });
};

function createUintNumberCodec(byteLength: number, littleEndian = false) {
  const codec = createUintBICodec(byteLength, littleEndian);
  return {
    __isFixedCodec__: true,
    byteLength,
    pack: (packable: BIish) => codec.pack(packable),
    unpack: (unpackable: Uint8Array) => codec.unpack(unpackable).toNumber(),
  };
}

function createBoolCodec() {
  const codec = createUintBICodec(1);
  return {
    __isFixedCodec__: true,
    byteLength: 1,
    pack: (packable: boolean) => codec.pack(packable ? 1 : 0),
    unpack: (unpackable: Uint8Array) => !codec.unpack(unpackable).isZero(),
  };
}

const Bool = createBoolCodec();

// Big endian so we can avoid conversion at smart contract side
const Uint8 = createUintNumberCodec(1);
const Uint16 = createUintNumberCodec(2);
const Uint24 = createUintNumberCodec(3);
const Uint32 = createUintNumberCodec(4);
const Uint40 = createUintBICodec(5);
const Uint48 = createUintBICodec(6);
const Uint56 = createUintBICodec(7);
const Uint64 = createUintBICodec(8);
const Uint72 = createUintBICodec(9);
const Uint80 = createUintBICodec(10);
const Uint88 = createUintBICodec(11);
const Uint96 = createUintBICodec(12);
const Uint104 = createUintBICodec(13);
const Uint112 = createUintBICodec(14);
const Uint120 = createUintBICodec(15);
const Uint128 = createUintBICodec(16);
const Uint136 = createUintBICodec(17);
const Uint144 = createUintBICodec(18);
const Uint152 = createUintBICodec(19);
const Uint160 = createUintBICodec(20);
const Uint168 = createUintBICodec(21);
const Uint176 = createUintBICodec(22);
const Uint184 = createUintBICodec(23);
const Uint192 = createUintBICodec(24);
const Uint200 = createUintBICodec(25);
const Uint208 = createUintBICodec(26);
const Uint216 = createUintBICodec(27);
const Uint224 = createUintBICodec(28);
const Uint232 = createUintBICodec(29);
const Uint240 = createUintBICodec(30);
const Uint248 = createUintBICodec(31);
const Uint256 = createUintBICodec(32);

// Adapted from https://github.com/ckb-js/lumos/blob/a243f118a1f5aff91ea282eebd3eff149fa562b1/packages/codec/src/molecule/layout.ts#L336C1-L370C2
// with custom union ID support
export function union<T extends Record<string, [AnyCodec, number]>>(
  itemCodecs: T,
): AnyCodec {
  return createBytesCodec({
    pack(obj) {
      const type = obj.type;

      /* c8 ignore next */
      if (typeof type !== "string") {
        throw new Error(
          `Invalid type in union: ${String(obj.type)}, which must be a string`,
        );
      }

      const itemCodec = itemCodecs[type];
      if (!itemCodec) {
        throw new Error(`Unknown union type: ${String(obj.type)}`);
      }
      const packedFieldId = bytify(Uint32LE.pack(itemCodec[1]));
      const packedBody = bytify(itemCodec[0].pack(obj.value));
      const result = new Uint8Array(packedFieldId.length + packedBody.length);
      result.set(packedFieldId);
      result.set(packedBody, packedFieldId.length);
      return result;
    },
    unpack(buf) {
      const typeId = Uint32LE.unpack(buf.slice(0, 4));
      const type = Object.keys(itemCodecs).find(
        (t) => itemCodecs[t][1] === typeId,
      );
      if (!type) {
        throw new Error(`Unknown union id: ${typeId}`);
      }
      const itemCodec = itemCodecs[type];
      return { type, value: itemCodec[0].unpack(buf.slice(4)) };
    },
  });
}

const parsed: CodecMap = createParser().parse(
  readFileSync(join(__dirname, "..", "schemas", "basic.mol")).toString("utf-8"),
);

export const top_level: CodecMap = Object.assign({}, parsed, {
  ExtendedWitness: union({
    SighashWithAction: [parsed.SighashWithAction, 4278190081],
    Sighash: [parsed.Sighash, 4278190082],
    Otx: [parsed.Otx, 4278190083],
    OtxStart: [parsed.OtxStart, 4278190084],
  }),
});
