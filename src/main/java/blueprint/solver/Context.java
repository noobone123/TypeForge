package blueprint.solver;

import blueprint.base.dataflow.TypeBuilder;
import blueprint.utils.Logging;
import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.HighSymbol;

import java.util.Collection;
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
     * Add a field to the current context. The field can be a primitive data type.
     * @param highSym the HighSymbol representing the variable that holds this structure type
     * @param offset the offset of the field within the structure
     * @param dt the field's data type if adding a DataType
     */
    public void addField(HighSymbol highSym, long offset, DataType dt) {
        ctx.computeIfAbsent(highSym, k -> new TypeBuilder()).addPrimitive(offset, dt);
    }

    public void addField(HighSymbol highSym, long offset, TypeBuilder builder) {
        ctx.computeIfAbsent(highSym, k -> new TypeBuilder()).addTypeBuilder(offset, builder);
    }

    /**
     * Merge the TypeBuilder of the other intraSolver's context to the current context.
     * @param other the other intraSolver's context
     * @param from the HighSymbol in the other context
     * @param to the HighSymbol in the current context
     * @param offset the offset of `to` highSymbol's field
     * @return true if the merge is successful
     */
    public boolean mergeFromOther(Context other, HighSymbol from, HighSymbol to, long offset) {
        if (!other.ctx.containsKey(from)) {
            Logging.error("No HighSymbol in the other context");
            return false;
        }

        var otherTypeBuilder = other.ctx.get(from);
        if (offset == 0) {
            ctx.put(to, otherTypeBuilder);
        } else {
            var typeBuilder = ctx.computeIfAbsent(to, k -> new TypeBuilder());
            typeBuilder.addTypeBuilder(offset, otherTypeBuilder);
            typeBuilder.addTag(offset, "ARGUMENT");
        }

        return true;
    }


    /**
     * If two Pointer highSymbols are alias intra-procedural. Then we should merge the TypeBuilder of
     * these two HighSymbols, which means the two HighSymbols will hold the same TypeBuilder.
     * @param a the HighSymbol a
     * @param b the HighSymbol b
     */
    public boolean setAliasIntra(HighSymbol a, HighSymbol b) {
        var typeBuilder_a = ctx.get(a);
        var typeBuilder_b = ctx.get(b);

        if (typeBuilder_a == null && typeBuilder_b == null) {
            return false;
        }

        if (typeBuilder_a != null) {
            typeBuilder_a.merge(typeBuilder_b);
            ctx.put(a, typeBuilder_a);
            ctx.put(b, typeBuilder_a);
        } else {
            ctx.put(a, typeBuilder_b);
            ctx.put(b, typeBuilder_b);
        }

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

    public Collection<HighSymbol> getHighSymbols() {
        return ctx.keySet();
    }

    public boolean isEmpty() {
        return ctx.isEmpty();
    }
}
