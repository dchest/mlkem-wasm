// TypeScript bindings for emscripten-generated code.  Automatically generated at compile time.
declare namespace RuntimeExports {
    /**
     * @param {number} ptr
     * @param {string} type
     */
    function getValue(ptr: number, type?: string): any;
    /**
     * @param {number} ptr
     * @param {number} value
     * @param {string} type
     */
    function setValue(ptr: number, value: number, type?: string): void;
    let HEAP8: any;
    let HEAPU8: any;
    function stackSave(): any;
    function stackAlloc(sz: any): any;
    function stackRestore(val: any): any;
}
interface WasmModule {
  _mlkem768_keypair_derand(_0: number, _1: number, _2: number): number;
  _mlkem768_enc_derand(_0: number, _1: number, _2: number, _3: number): number;
  _mlkem768_dec(_0: number, _1: number, _2: number): number;
}

export type MainModule = WasmModule & typeof RuntimeExports;
export default function MainModuleFactory (options?: unknown): Promise<MainModule>;
