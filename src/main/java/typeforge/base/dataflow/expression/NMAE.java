package typeforge.base.dataflow.expression;

import typeforge.base.node.CallSite;
import typeforge.utils.Logging;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.Varnode;

import java.util.*;

/**
 * NMAE (Nested Member Access Expression) represents all expressions in program that can be represented as:
 *  <p> base + index * scale + offset </p>
 */
public class NMAE {

    public enum Attribute {
        ARGUMENT,
        RETURN,
        ARRAY,
        STRUCT,
        UNION,
        GLOBAL,
        POINTER_TO_STRUCT,
        POINTER_TO_UNION,
        MAY_ARRAY_PTR,
        CODE_PTR
    }

    public NMAE baseExpr = null;
    public NMAE indexExpr = null;
    public NMAE scaleExpr = null;
    public NMAE offsetExpr = null;

    public HighSymbol rootSym = null;

    public long constant = 0;
    public CallSite callSite = null;
    public int argIndex = -1;

    public boolean dereference = false;
    public boolean reference = false;
    public NMAE nestedExpr = null;

    public Function function = null;
    public String prefix = null;

    private boolean isNormalConst = false;
    private boolean isArgConst = false;
    public boolean isGlobal = false;
    public Address globalAddr = null;

    public boolean isParameter = false;
    public boolean isReturnVal = false;

    public boolean isTemp;
    public Varnode varnode;

    public Set<Attribute> attributes = new HashSet<>();

    public NMAE(NMAEManager.Builder builder) {
        // Be careful, for global variables, the same global variable have different HighSymbol instances
        // in different functions.
        this.baseExpr = builder.baseExpr;
        this.indexExpr = builder.indexExpr;
        this.scaleExpr = builder.scaleExpr;
        this.offsetExpr = builder.offsetExpr;
        this.rootSym = builder.rootSym;
        this.constant = builder.constant;
        this.callSite = builder.callSite;
        this.argIndex = builder.argIndex;
        this.dereference = builder.dereference;
        this.reference = builder.reference;
        this.nestedExpr = builder.nestedExpr;
        this.isNormalConst = builder.isNormalConst;
        this.isArgConst = builder.isArgConst;
        this.isGlobal = builder.isGlobal;
        this.globalAddr = builder.globalAddr;
        this.isTemp = builder.isTemp;
        this.varnode = builder.temp;

        if (this.dereference && this.nestedExpr == null) {
            throw new IllegalArgumentException("Dereference expression must have a nested expression.");
        }

        if (this.hasOffset() && this.dereference) {
            throw new IllegalArgumentException("Dereference expression cannot have offset.");
        }

        if (isGlobal) {
            this.prefix = "[Global]";
        } else if (isArgConst()) {
            this.prefix = String.format("[ConstArg-%s-%d]", this.callSite, this.argIndex);
            this.function = callSite.caller;
        } else if (isNormalConst()) {
            this.prefix = "[Constant]";
        } else if (isTemp) {
            this.prefix = "[Temp]";
        } else {
            var rootSymbol = getRootSymExpr().getRootSymbol();
            this.function = rootSymbol.getHighFunction().getFunction();
            this.prefix = String.format("[%s-%s]", this.function.getEntryPoint().toString(), this.function.getName());
        }

        Logging.trace("SymbolExpr","Created new SymbolExpr: " + this);
    }

    public NMAE getBase() {
        return baseExpr;
    }

    public NMAE getOffset() {
        return offsetExpr;
    }

    public NMAE getIndex() {
        return indexExpr;
    }

    public NMAE getScale() {
        return scaleExpr;
    }

    public long getConstant() {
        return constant;
    }

    public CallSite getCallSite() {
        if (isArgConst && callSite != null && argIndex != -1) {
            return callSite;
        }
        return null;
    }

    public int getArgIndex() {
        if (isArgConst && callSite != null && argIndex != -1) {
            return argIndex;
        }
        return -1;
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
        return isNormalConst && constant != 0;
    }

    public boolean isNormalConst() {
        return isNormalConst;
    }

    public boolean isArgConst() {
        return isArgConst && callSite != null && argIndex != -1;
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

    public NMAE getNestedExpr() {
        return nestedExpr;
    }

    public boolean isGlobal() {
        return isGlobal;
    }

    public NMAE getRootSymExpr() {
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

    public Function getFunction() {
        return function;
    }

    public void addAttribute(Attribute attr) {
        attributes.add(attr);
    }

    public boolean hasAttribute(Attribute attr) {
        return attributes.contains(attr);
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
        else if (isNormalConst) {
            sb.append("0x").append(Long.toHexString(constant));
        }
        else if (isArgConst) {
            sb.append("0x").append(Long.toHexString(constant));
        }
        else if (isTemp) {
            sb.append(varnode.toString());
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
              !hasAttribute(Attribute.POINTER_TO_STRUCT)) {
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
        else if (isTemp) {
            return Objects.hash(varnode);
        }
        else {
            return Objects.hash(baseExpr, indexExpr, scaleExpr,
                    offsetExpr, rootSym, constant, callSite, argIndex,
                    dereference, reference, nestedExpr,
                    isNormalConst, isArgConst);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof NMAE that)) return false;
        return this.hashCode() == that.hashCode();
    }

    @Override
    public String toString() {
        return String.format("%s: %s", prefix, getRepresentation());
    }
}