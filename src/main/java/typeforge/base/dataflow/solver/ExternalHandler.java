package typeforge.base.dataflow.solver;

import typeforge.base.dataflow.expression.NMAEManager;
import typeforge.base.node.CallSite;
import typeforge.utils.Logging;

import java.util.HashMap;
import java.util.Map;

/**
 * Handler for external function calls.
 */
public class ExternalHandler {

    /**
     * Base handler class for external functions
     */
    public static abstract class Handler {
        /**
         * Process an external function call
         */
        public abstract void handle(CallSite callSite, IntraSolver intraSolver, NMAEManager exprManager);
    }

    public static class Malloc extends Handler {
        @Override
        public void handle(CallSite callSite, IntraSolver intraSolver, NMAEManager exprManager) {
            var ptrExprs = intraSolver.getDataFlowFacts(callSite.receiver);
            for (var expr: ptrExprs) {
                Logging.info("ExternalHandler.Malloc",
                        String.format("Set composite of constraint: %s to true", expr));
                var constraint = exprManager.getOrCreateConstraint(expr);
                constraint.setComposite(true);

                var mallocSize = callSite.arguments.get(0);
                if (mallocSize.isConstant()) {
                    constraint.setSizeFromCallSite(mallocSize.getOffset(), callSite);
                    Logging.info("ExternalHandler.Malloc",
                            String.format("Set size of constraint: %s to %d", expr, callSite.arguments.get(0).getOffset()));
                }
            }
        }
    }

    public static class Calloc extends Handler {
        @Override
        public void handle(CallSite callSite, IntraSolver intraSolver, NMAEManager exprManager) {
            var ptrExprs = intraSolver.getDataFlowFacts(callSite.receiver);
            for (var expr: ptrExprs) {
                Logging.info("ExternalHandler.Calloc",
                        String.format("Set composite of constraint: %s to true", expr));
                var constraint = exprManager.getOrCreateConstraint(expr);
                constraint.setComposite(true);

                var nmemblock = callSite.arguments.get(0);
                var memsize = callSite.arguments.get(1);
                if (nmemblock.isConstant() && memsize.isConstant()) {
                    constraint.setSizeFromCallSite(nmemblock.getOffset() * memsize.getOffset(), callSite);
                    Logging.info("ExternalHandler.Calloc",
                            String.format("Set size of constraint: %s to %d", expr, nmemblock.getOffset() * memsize.getOffset()));
                }
            }
        }
    }

    /**
     * Handler for memset function.
     * For memset-like functions, the first pointer argument is treated as a composite type.
     * Because in the vast majority of scenarios, memset is used to initialize composite types,
     * regardless of whether their length is a constant.
     */
    public static class Memset extends Handler {
        @Override
        public void handle(CallSite callSite, IntraSolver intraSolver, NMAEManager exprManager) {
            var lengthArg = callSite.arguments.get(2);

            var ptrExprs = intraSolver.getDataFlowFacts(callSite.arguments.get(0));
            for (var expr: ptrExprs) {
                Logging.info("ExternalHandler.Memset",
                        String.format("Set composite of constraint: %s to true", expr));
                var constraint = exprManager.getOrCreateConstraint(expr);
                constraint.setComposite(true);

                if (lengthArg.isConstant()) {
                    constraint.setSizeFromCallSite(lengthArg.getOffset(), callSite);
                    Logging.info("ExternalHandler.Memset",
                            String.format("Set size of constraint: %s to %d", expr, lengthArg.getOffset()));
                }
            }
        }
    }

    /**
     * Handler for memcpy function.
     * For memcpy-like functions, the dst and src pointer arguments are treated as composite types
     * only if the length argument is a constant.
     * Because in other cases, the memcpy function is used to copy data from *char[]
     */
    public static class Memcpy extends Handler {
        @Override
        public void handle(CallSite callSite, IntraSolver intraSolver, NMAEManager exprManager) {
            var dstVn = callSite.arguments.get(0);
            var srcVn = callSite.arguments.get(1);
            var lengthVn = callSite.arguments.get(2);
            if (!intraSolver.isTracedVn(dstVn) || !intraSolver.isTracedVn(srcVn)) {
                return;
            }
            var dstExprs = intraSolver.getDataFlowFacts(dstVn);
            var srcExprs = intraSolver.getDataFlowFacts(srcVn);
            for (var dstExpr : dstExprs) {
                for (var srcExpr : srcExprs) {
                    var dstConstraint = exprManager.getOrCreateConstraint(dstExpr);
                    var srcConstraint = exprManager.getOrCreateConstraint(srcExpr);

                    if (lengthVn.isConstant()) {
                        dstConstraint.setComposite(true);
                        dstConstraint.setSizeFromCallSite(lengthVn.getOffset(), callSite);
                        srcConstraint.setComposite(true);
                        srcConstraint.setSizeFromCallSite(lengthVn.getOffset(), callSite);
                        Logging.info("ExternalHandler.Memcpy",
                                String.format("Set size and composite from %s -> %s with size %d", srcExpr, dstExpr, lengthVn.getOffset()));
                    }
                }
            }
        }
    }

    // Map of function names to their handlers
    private static final Map<String, Handler> HANDLERS = new HashMap<>();

    static {
        HANDLERS.put("memset", new Memset());
        HANDLERS.put("memcpy", new Memcpy());
        HANDLERS.put("mempcpy", new Memcpy());
        HANDLERS.put("malloc", new Malloc());
        HANDLERS.put("calloc", new Calloc());
        // `calloc` and `malloc` are always used for allocating heap buffer for composite types
        // while `realloc` is used for reallocating heap buffer for `char*`
    }

    /**
     * Handle an external function call
     */
    public static void handle(CallSite callSite, String funcName, IntraSolver intraSolver, NMAEManager exprManager) {
        Handler handler = HANDLERS.get(funcName);
        if (handler != null) {
            handler.handle(callSite, intraSolver, exprManager);
        }
    }
}