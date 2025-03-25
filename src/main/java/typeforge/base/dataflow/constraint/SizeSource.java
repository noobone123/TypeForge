package typeforge.base.dataflow.constraint;

import typeforge.base.dataflow.expression.NMAE;
import typeforge.base.node.CallSite;
import typeforge.utils.Logging;

/**
 * Tracks the source of size information for a TypeConstraint.
 */
public class SizeSource {

    public enum SourceType {
        CALLSITE,   // Size determined from a function call
        EXPRESSION   // Size determined from an expression within a function
    }

    private final long size;
    private final SourceType sourceType;
    private final NMAE expression; // For expression sources only
    private final CallSite callSite; // For call site sources only

    /**
     * Creates a SizeSource from a function call
     */
    public SizeSource(long size, CallSite callSite) {
        this.size = size;
        this.sourceType = SourceType.CALLSITE;
        this.callSite = callSite;
        this.expression = null;
    }

    /**
     * Creates a SizeSource from an expression
     */
    public SizeSource(long size, NMAE expression) {
        this.size = size;
        this.sourceType = SourceType.EXPRESSION;
        this.expression = expression;
        this.callSite = null;
    }

    public long getSize() {
        return size;
    }

    public SourceType getSourceType() {
        return sourceType;
    }

    @Override
    public String toString() {
        if (sourceType == SourceType.CALLSITE) {
            return String.format("SizeSource{size=%d, callsite=%s}",
                    size, callSite);
        } else {
            return String.format("SizeSource{size=%d, expr=%s}",
                    size, expression);
        }
    }
}