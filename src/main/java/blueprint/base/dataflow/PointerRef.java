package blueprint.base.dataflow;

import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;


/**
 * VarNode with data-flow traceable to base pointer.
 * For example, If there is a statement like following:
 * <p>
 *     <code> varnode_1 = *(varnode_0 + 4) </code>
 *     <code> varnode_2 = *(varnode_1 + 4) </code>
 * </p>
 *
 * varnode_0 is the original pointer, varnode_1's offset is 4, varnode_2's offset is 8
 */
public class PointerRef {
    public Varnode base;           // The base pointer
    public Varnode current;		// The current pointer
    public long offset;			// Offset relative to ** Base ** pointer

    public PointerRef(Varnode ref, Varnode base, long off) {
        this.base = base;
        current = ref;
        offset = off;
    }

    @Override
    public String toString() {
        var currentAST = (VarnodeAST) current;
        var baseAST = (VarnodeAST) base;
        return "PointerRef{ " +
                "curr = " + currentAST.getUniqueId() + "_" + currentAST +  ", " +
                "base = " + baseAST.getUniqueId() + "_" + baseAST + ", " +
                "offset = 0x" + Long.toHexString(offset) +
                " }";
    }
}