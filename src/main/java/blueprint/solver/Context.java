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

    public void addDataType(HighSymbol highSym, long offset, DataType dt) {
        if (!ctx.containsKey(highSym)) {
            ctx.put(highSym, new TypeBuilder());
        }

        var typeBuilder = ctx.get(highSym);
        typeBuilder.addDataType(offset, dt);
    }

    public void dump() {
        for (var entry : ctx.entrySet()) {
            Logging.info("HighSymbol: " + entry.getKey().getName());
            Logging.info("TypeBuilder: " + entry.getValue().toString());
        }
    }
}
