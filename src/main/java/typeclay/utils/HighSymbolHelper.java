package typeclay.utils;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.HighSymbol;

public class HighSymbolHelper {

    public static Address getGlobalHighSymbolAddr(HighSymbol globalSym) {
        assert globalSym.isGlobal();
        return globalSym.getStorage().getMinAddress();
    }
}
