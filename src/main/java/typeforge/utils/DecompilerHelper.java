package typeforge.utils;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.DecompileConfigurer;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.MetaDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

import java.util.HashMap;
import java.util.Iterator;

public class DecompilerHelper {

    /**
     * For more information about the decompiler, please refer to the official documentation:
     * <a href="https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html">...</a>
     * @return DecompInterface
     */
    public static DecompInterface setUpDecompiler(DecompileOptions options) {
        DecompInterface ifc = new DecompInterface();
        if (options != null) {
            ifc.setOptions(options);
        }
        ifc.toggleCCode(true);
        ifc.toggleSyntaxTree(true);
        return ifc;
    }

    public static void setLocalVariableDataType(HighSymbol highSym, DataType dt, int ptrLevel) {
        try {
            var updatedDT = DataTypeHelper.getPointerDT(dt, ptrLevel);
            HighFunctionDBUtil.updateDBVariable(highSym, null, updatedDT, SourceType.USER_DEFINED);
            Logging.info("DecompilerHelper", "Set data type for local variable: " + highSym.getName() + " to " + updatedDT.getName());
        } catch (Exception e) {
            Logging.error("DecompilerHelper", "Failed to set data type for local variable: " + highSym.getName());
        }
    }


    public static void setLocalVariableDataType(HighSymbol highSym, DataType dt) {
        try {
            HighFunctionDBUtil.updateDBVariable(highSym, null, dt, SourceType.USER_DEFINED);
            Logging.info("DecompilerHelper", "Set data type for local variable: " + highSym.getName() + " to " + dt.getName());
        } catch (Exception e) {
            Logging.error("DecompilerHelper", "Failed to set data type for local variable: " + highSym.getName());
        }
    }

    public static DecompileResults decompile(Function func) {
        DecompInterface ifc = DecompilerHelper.setUpDecompiler(null);
        try {
            if (!ifc.openProgram(Global.currentProgram)) {
                Logging.error("FunctionNode", "Failed to use the decompiler");
                return null;
            }

            DecompileResults decompileRes = ifc.decompileFunction(func, 30, TaskMonitor.DUMMY);
            if (!decompileRes.decompileCompleted()) {
                Logging.error("FunctionNode", "Function decompile failed" + func.getName());
            } else {
                Logging.info("FunctionNode", "Decompiled function " + func.getName());
            }
            return decompileRes;
        } finally {
            ifc.dispose();
        }
    }

    /**
     * Callback for parallel decompile, used for initializing function node
     */
    public static class ParallelPrepareFunctionNodeCallBack extends DecompilerCallback<Void> {

        public HashMap<Address, DecompileResults> addrToDecRes = new HashMap<>();
        public int decompileCount = 0;

        // TODO: store Function->FunctionNode mapping here, then update FunctionNode info in `process` function.
        public ParallelPrepareFunctionNodeCallBack(Program program, DecompileConfigurer configurer) {
            super(program, configurer);
        }

        @Override
        public Void process(DecompileResults decompileResults, TaskMonitor taskMonitor) throws Exception {
            addrToDecRes.put(
                    decompileResults.getFunction().getEntryPoint(),
                    decompileResults
            );
            decompileCount += 1;
            return null;
        }
    }


    public static class Location {
        private Function func;
        private int stackOffset;
        private String paramName;
        private Address PCAddr;

        public Location(Function func, int stackOffset) {
            this.func = func;
            this.stackOffset = stackOffset;
        }

        public Location(Function func, String paramName) {
            this.func = func;
            this.paramName = paramName;
        }

        public Location(Function func, Address pcAddr) {
            this.func = func;
            this.PCAddr = pcAddr;
        }

        @Override
        public String toString() {
            var funcEA = String.format("0x%x", func.getEntryPoint().getOffset());
            if (stackOffset != 0) {
                String loc;
                if (stackOffset > 0) {
                    loc = String.format("stack[0x%x]", stackOffset);
                } else {
                    loc = String.format("stack[-0x%x]", -stackOffset);
                }
                return String.format("%s:%s", funcEA, loc);
            }
            else if (paramName != null) {
                return String.format("%s:%s", funcEA, paramName);
            } else {
                var loc = String.format("RegUniq[0x%x]", PCAddr != null ? PCAddr.getOffset() : 0);
                return String.format("%s:%s", funcEA, loc);
            }
        }

        @Override
        public int hashCode() {
            if (stackOffset != 0) {
                return func.hashCode() + stackOffset;
            } else if (paramName != null) {
                return func.hashCode() + paramName.hashCode();
            } else {
                return func.hashCode() + PCAddr.hashCode();
            }
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) {
                return true;
            }
            if (!(obj instanceof Location loc)) {
                return false;
            }
            if (stackOffset != 0) {
                return func.equals(loc.func) && stackOffset == loc.stackOffset;
            } else if (paramName != null) {
                return func.equals(loc.func) && paramName.equals(loc.paramName);
            } else {
                return func.equals(loc.func) && PCAddr.equals(loc.PCAddr);
            }
        }

        public static Location getLocation(HighSymbol sym) {
            if (sym.isParameter()) {
                return new Location(sym.getHighFunction().getFunction(), sym.getName());
            } else {
                var storage = sym.getStorage();
                if (storage.isStackStorage()) {
                    return new Location(sym.getHighFunction().getFunction(), storage.getStackOffset());
                } else if (storage.isRegisterStorage()) {
                    return new Location(sym.getHighFunction().getFunction(), sym.getPCAddress());
                } else if (storage.isUniqueStorage()) {
                    return new Location(sym.getHighFunction().getFunction(), sym.getPCAddress());
                }
                return null;
            }
        }

        public static Location getLocation(HighSymbol sym, String paramName) {
            if (sym.isParameter()) {
                return new Location(sym.getHighFunction().getFunction(), paramName);
            } else {
                Logging.error("Location", "Failed to get location for symbol: " + sym.getName());
                return null;
            }
        }
    }


    public static class ClayCallBack extends DecompilerCallback<Void> {

        public HashMap<Address, String> addrToCodeMap;
        public HashMap<Location, HighSymbol> locationToSymMap;

        public ClayCallBack(Program program, DecompileConfigurer configurer) {
            super(program, configurer);
            addrToCodeMap = new HashMap<>();
            locationToSymMap = new HashMap<>();
        }

        @Override
        public Void process(DecompileResults decompileResults, TaskMonitor taskMonitor) throws Exception {
            if (decompileResults != null && decompileResults.decompileCompleted()) {
                String code = decompileResults.getDecompiledFunction().getC();
                addrToCodeMap.put(decompileResults.getFunction().getEntryPoint(), code);

                var localSymMap = decompileResults.getHighFunction().getLocalSymbolMap();
                for (Iterator<HighSymbol> it = localSymMap.getSymbols(); it.hasNext(); ) {
                    var sym = it.next();
                    var location = Location.getLocation(sym);
                    locationToSymMap.put(location, sym);
                }
            }
            return null;
        }

        public HighSymbol getHighSymbolByOldHighSym(HighSymbol old) {
            if (old == null) { return null; }
            var location = Location.getLocation(old);
            return locationToSymMap.get(location);
        }
    }


    /**
     * Get the data-type associated with a Varnode.  If the Varnode is input to a CAST p-code
     * op, take the most specific data-type between what it was cast from and cast to.
     * @param vn is the Varnode to get the data-type for
     * @return the data-type
     */
    public static DataType getDataTypeTraceForward(Varnode vn) {
        DataType res = vn.getHigh().getDataType();
        PcodeOp op = vn.getLoneDescend();
        if (op != null && op.getOpcode() == PcodeOp.CAST) {
            Varnode otherVn = op.getOutput();
            res = MetaDataType.getMostSpecificDataType(res, otherVn.getHigh().getDataType());
        }
        return res;
    }


    /**
     * Get the data-type associated with a Varnode.  If the Varnode is produce by a CAST p-code
     * op, take the most specific data-type between what it was cast from and cast to.
     * @param vn is the Varnode to get the data-type for
     * @return the data-type
     */
    public static DataType getDataTypeTraceBackward(Varnode vn) {
        DataType res = vn.getHigh().getDataType();
        PcodeOp op = vn.getDef();
        if (op != null && op.getOpcode() == PcodeOp.CAST) {
            Varnode otherVn = op.getInput(0);
            res = MetaDataType.getMostSpecificDataType(res, otherVn.getHigh().getDataType());
        }
        return res;
    }


    /**
     * Get Signed value of a const varnode
     * @param varnode the const varnode
     * @return signed value
     */
    public static long getSigned(Varnode varnode) {
        assert varnode.isConstant();
        // mask the sign bit
        long mask = 0x80L << ((varnode.getSize() - 1) * 8);
        // constant's value is actually unsigned offset in pcode's address space
        long value = varnode.getOffset();
        if ((value & mask) != 0) {
            value |= (0xffffffffffffffffL << ((varnode.getSize() - 1) * 8));
        }
        return value;
    }


    public static String getVarnodeString(VarnodeAST v) {
        String retstr = "";
        retstr += v.getUniqueId() + "_";
        retstr += v.toString();

        //include HighVariable information if it's there
        //but don't output UNNAMED a ton of times
        if (v.getHigh() != null) {
            if (v.getHigh().getSymbol() == null) {
                retstr += "[noHighSym]";
            } else {
                retstr += "[" + v.getHigh().getSymbol().getName() + "]";
            }
        }
        return retstr;
    }
}
