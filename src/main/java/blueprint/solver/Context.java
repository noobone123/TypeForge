package blueprint.solver;

import blueprint.utils.Logging;
import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.HighSymbol;

import java.util.HashMap;

/**
 * The context used to store the relationship between HighSymbol and TypeBuilder.
 * Each IntraSolver holds a Context.
 */
public class Context {

    private final HashMap<HighSymbol, TypeBuilder> ctx;

    public Context() {
        this.ctx = new HashMap<>();
    }

    /**
     * Add a data type to the current context
     * @param highSym the HighSymbol
     * @param offset the offset of the field
     * @param dt the field's data type
     */
    public void addDataType(HighSymbol highSym, long offset, DataType dt) {
        if (!ctx.containsKey(highSym)) {
            ctx.put(highSym, new TypeBuilder());
        }

        var typeBuilder = ctx.get(highSym);
        typeBuilder.addDataType(offset, dt);
    }

    /**
     * Merge the TypeBuilder of the other context to the current context.
     * @param other the other intraSolver's context
     * @param from the HighSymbol in the other context
     * @param to the HighSymbol in the current context
     * @return true if the merge is successful
     */
    public boolean merge(Context other, HighSymbol from, HighSymbol to) {
        if (!other.ctx.containsKey(from)) {
            Logging.error("No HighSymbol in the other context");
            return false;
        }

        ctx.put(to, other.ctx.get(from));
        return true;
    }

    /**
     * Dump the current context to the log
     */
    public void dump() {
        for (var entry : ctx.entrySet()) {
            Logging.info("HighSymbol: " + entry.getKey().getName());
            Logging.info("TypeBuilder: " + entry.getValue().toString());
        }
    }
}
