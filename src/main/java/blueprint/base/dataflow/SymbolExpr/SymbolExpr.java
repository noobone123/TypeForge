package blueprint.base.dataflow.SymbolExpr;

import blueprint.base.dataflow.typeAlias.TypeAliasGraph;
import blueprint.base.dataflow.context.InterContext;
import blueprint.utils.Logging;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighSymbol;

import java.util.*;

/**
 * SymbolExpr represents all expressions in program that can be represented as :
 *  <p> base + index * scale + offset </p>
 */
public class SymbolExpr {

    public enum Attribute {
        ARGUMENT,
        RETURN,
        ARRAY,
        STRUCT,
        UNION,
        GLOBAL,
        POINTER_TO_COMPOSITE,
        MAY_ARRAY_PTR,
        CODE_PTR
    }


    public SymbolExpr baseExpr = null;
    public SymbolExpr indexExpr = null;
    public SymbolExpr scaleExpr = null;
    public SymbolExpr offsetExpr = null;

    public HighSymbol rootSym = null;
    public long constant = 0;
    public boolean dereference = false;
    public boolean reference = false;
    public SymbolExpr nestedExpr = null;

    public Function function = null;
    public String prefix = null;

    public boolean isConst = false;
    public boolean isGlobal = false;
    public Address globalAddr = null;

    public Set<Attribute> attributes = new HashSet<>();
    public long variableSize = 0;

    public SymbolExpr(SymbolExprManager.Builder builder) {
        // Be careful, for global variables, the same global variable have different HighSymbol instances
        // in different functions.
        // TODO: what about Global variable's complex SymbolExpr?
        this.baseExpr = builder.baseExpr;
        this.indexExpr = builder.indexExpr;
        this.scaleExpr = builder.scaleExpr;
        this.offsetExpr = builder.offsetExpr;
        this.rootSym = builder.rootSym;
        this.constant = builder.constant;
        this.dereference = builder.dereference;
        this.reference = builder.reference;
        this.nestedExpr = builder.nestedExpr;
        this.isConst = builder.isConst;
        this.isGlobal = builder.isGlobal;
        this.globalAddr = builder.globalAddr;

        if (this.dereference && this.nestedExpr == null) {
            throw new IllegalArgumentException("Dereference expression must have a nested expression.");
        }

        if (this.hasOffset() && this.dereference) {
            throw new IllegalArgumentException("Dereference expression cannot have offset.");
        }

        if (isGlobal) {
            this.prefix = "Global";
        } else if (isConst()) {
            this.prefix = "Constant";
        } else {
            var rootSymbol = getRootSymExpr().getRootSymbol();
            this.function = rootSymbol.getHighFunction().getFunction();
            this.prefix = this.function.getName();
        }

        Logging.info("SymbolExpr","Created new SymbolExpr: " + this);
    }

    public SymbolExpr getBase() {
        return baseExpr;
    }

    public SymbolExpr getOffset() {
        return offsetExpr;
    }

    public SymbolExpr getIndex() {
        return indexExpr;
    }

    public SymbolExpr getScale() {
        return scaleExpr;
    }

    public long getConstant() {
        return constant;
    }

    public boolean hasOffset() {
        return offsetExpr != null;
    }

    public boolean hasBase() {
        return baseExpr != null;
    }

    public boolean hasIndexScale() {
        return indexExpr != null && scaleExpr != null;
    }

    public boolean isNoZeroConst() {
        return isConst && constant != 0;
    }

    public boolean isConst() {
        return isConst;
    }

    public boolean isRootSymExpr() {
        return baseExpr == null && indexExpr == null && scaleExpr == null && offsetExpr == null && rootSym != null && constant == 0;
    }

    public HighSymbol getRootSymbol() {
        return rootSym;
    }

    public boolean isDereference() {
        assert baseExpr == null && indexExpr == null && scaleExpr == null && offsetExpr == null && rootSym == null && constant == 0;
        return dereference;
    }

    public boolean isReference() {
        return reference;
    }

    public SymbolExpr getNestedExpr() {
        return nestedExpr;
    }

    public boolean isGlobal() {
        return isGlobal;
    }

    public SymbolExpr getRootSymExpr() {
        if (isRootSymExpr()) {
            return this;
        }
        else if (isDereference() && nestedExpr != null) {
            return nestedExpr.getRootSymExpr();
        }
        else if (isReference() && nestedExpr != null) {
            return nestedExpr.getRootSymExpr();
        }
        else if (baseExpr != null) {
            return baseExpr.getRootSymExpr();
        }
        else if (indexExpr != null) {
            return indexExpr.getRootSymExpr();
        }
        Logging.error("SymbolExpr", String.format("[SymbolExpr] Cannot find representative root SymExpr for %s", this));
        return null;
    }

    public void addAttribute(Attribute attr) {
        attributes.add(attr);
    }

    public boolean hasAttribute(Attribute attr) {
        return attributes.contains(attr);
    }

    public void setVariableSize(long size) {
        this.variableSize = size;
    }

    public List<Attribute> getAttributes() {
        return new ArrayList<>(attributes);
    }

    public boolean isVariable() {
        if (isRootSymExpr()) {
            return true;
        } else if (isReference() && nestedExpr.isRootSymExpr()) {
            return true;
        } else {
            return false;
        }
    }

    public HighSymbol getRootHighSymbol() {
        return getRootSymExpr().getRootSymbol();
    }


    public String getRepresentation() {
        StringBuilder sb = new StringBuilder();
        if (rootSym != null) {
            sb.append(rootSym.getName());
        }
        else if (isConst) {
            sb.append("0x").append(Long.toHexString(constant));
        }
        else if (dereference) {
            sb.append(String.format("*%s", nestedExpr.getRepresentation()));
        }
        else if (reference) {
            sb.append(String.format("&%s", nestedExpr.getRepresentation()));
        }
        else {
            sb.append("(");
            if (baseExpr != null) {
                sb.append(baseExpr.getRepresentation());
            }
            if (baseExpr != null && indexExpr != null) {
                sb.append(" + ");
            }
            if (indexExpr != null) {
                sb.append(indexExpr.getRepresentation()).append(" * ").append(scaleExpr.getRepresentation());
            }
            if ((baseExpr != null || indexExpr != null) && offsetExpr != null) {
                sb.append(" + ");
            }
            if (offsetExpr != null) {
                sb.append(offsetExpr.getRepresentation());
            }
            sb.append(")");
        }

        if ((hasAttribute(Attribute.ARRAY) || hasAttribute(Attribute.STRUCT) || hasAttribute(Attribute.UNION)) &&
              !hasAttribute(Attribute.POINTER_TO_COMPOSITE)) {
            sb.append("[Composite]");
        }

        return sb.toString();
    }

    // IMPORTANT: modified the equals and hashCode should be careful the cache mechanism in Builder
    @Override
    public int hashCode() {
        if (isGlobal) {
            return Objects.hash(globalAddr, indexExpr, scaleExpr,
                    offsetExpr, constant, dereference, reference, nestedExpr);
        }
        else {
            return Objects.hash(baseExpr, indexExpr, scaleExpr,
                    offsetExpr, rootSym, constant,
                    dereference, reference, nestedExpr,
                    isConst);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SymbolExpr that)) return false;
        return this.hashCode() == that.hashCode();
    }

    @Override
    public String toString() {
        return String.format("%s: %s", prefix, getRepresentation());
    }
}