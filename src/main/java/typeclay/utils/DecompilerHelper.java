package typeclay.utils;

import generic.concurrent.QCallback;
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


    public static class ClayCallBack extends DecompilerCallback<Void> {

        public HashMap<Address, String> addrToCodeMap;

        public ClayCallBack(Program program, DecompileConfigurer configurer) {
            super(program, configurer);
            addrToCodeMap = new HashMap<Address, String>();
        }

        @Override
        public Void process(DecompileResults decompileResults, TaskMonitor taskMonitor) throws Exception {
            if (decompileResults != null && decompileResults.decompileCompleted()) {
                String code = decompileResults.getDecompiledFunction().getC();
                addrToCodeMap.put(decompileResults.getFunction().getEntryPoint(), code);
            }
            return null;
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
