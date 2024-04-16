package blueprint.utils;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.MetaDataType;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;

public class DecompilerHelper {

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
}
