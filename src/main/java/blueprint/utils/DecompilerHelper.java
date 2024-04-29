package blueprint.utils;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.MetaDataType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;

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
     * Dump HighVariable's HighPcode
     */
    public static void dumpHighPcode(HighFunction high) {
        for (var block : high.getBasicBlocks()) {
            Logging.info("Block: " + block.getIndex());
            var iter = block.getIterator();
            while (iter.hasNext()) {
                PcodeOp op = iter.next();

                StringBuilder highPcodeInst = new StringBuilder();

                //Output Pcode op's output Varnode
                VarnodeAST outVn = (VarnodeAST) op.getOutput();
                if (outVn != null) {
                    highPcodeInst.append(getVarnodeString(outVn));
                } else {
                    highPcodeInst.append("---"); //op with no output
                }

                //Output opcode itself
                highPcodeInst.append("," + " ").append(op.getMnemonic());

                // TODO: handle INDIRECT opcodes.
                if (op.getOpcode() == PcodeOp.CALL) {
                    var calleeAddr = op.getInput(0).getAddress();
                    // get Callee Function
                    var callee = Global.flatAPI.getFunctionAt(calleeAddr);
                    String calleeName;
                    if (callee != null) {
                        calleeName = callee.getName();
                    } else {
                        calleeName = calleeAddr.toString();
                    }
                    highPcodeInst.append(" ").append(calleeName);
                }

                //Output Pcode op's input Varnodes
                for (int i = 0; i < op.getNumInputs(); ++i) {
                    highPcodeInst.append("," + " ").append(getVarnodeString((VarnodeAST) op.getInput(i)));
                }

                // Logging.info(op.getSeqnum().toString() + " => " + highPcodeInst);
                Logging.info(highPcodeInst.toString());
            }
        }
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


    protected static String getVarnodeString(VarnodeAST v) {
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
