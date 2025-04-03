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
            var ptrExprs = intraSolver.getOrCreateDataFlowFacts(callSite.receiver);
            for (var expr: ptrExprs) {
                Logging.debug("ExternalHandler.Malloc",
                        String.format("Set composite of skeleton: %s to true", expr));
                var skeleton = exprManager.getOrCreateSkeleton(expr);
                skeleton.setComposite(true);

                var mallocSize = callSite.arguments.get(0);
                if (mallocSize.isConstant()) {
                    skeleton.setSizeFromCallSite(mallocSize.getOffset(), callSite);
                    Logging.debug("ExternalHandler.Malloc",
                            String.format("(malloc) Set size of skeleton : %s to 0x%x", expr, callSite.arguments.get(0).getOffset()));
                }
            }
        }
    }

    public static class Calloc extends Handler {
        @Override
        public void handle(CallSite callSite, IntraSolver intraSolver, NMAEManager exprManager) {
            var ptrExprs = intraSolver.getOrCreateDataFlowFacts(callSite.receiver);
            for (var expr: ptrExprs) {
                Logging.debug("ExternalHandler.Calloc",
                        String.format("Set composite of skeleton: %s to true", expr));
                var skeleton = exprManager.getOrCreateSkeleton(expr);
                skeleton.setComposite(true);

                var nmemblock = callSite.arguments.get(0);
                var memsize = callSite.arguments.get(1);
                if (nmemblock.isConstant() && memsize.isConstant()) {
                    skeleton.setSizeFromCallSite(nmemblock.getOffset() * memsize.getOffset(), callSite);
                    Logging.debug("ExternalHandler.Calloc",
                            String.format("(calloc) Set size of skeleton: %s to 0x%x", expr, nmemblock.getOffset() * memsize.getOffset()));
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

            var ptrExprs = intraSolver.getOrCreateDataFlowFacts(callSite.arguments.get(0));
            for (var expr: ptrExprs) {
                Logging.debug("ExternalHandler.Memset",
                        String.format("(memset) Set composite of skeleton: %s to true", expr));
                var skeleton = exprManager.getOrCreateSkeleton(expr);
                skeleton.setComposite(true);

                if (lengthArg.isConstant()) {
                    skeleton.setSizeFromCallSite(lengthArg.getOffset(), callSite);
                    Logging.debug("ExternalHandler.Memset",
                            String.format("(memset) Set size of skeleton: %s to %d", expr, lengthArg.getOffset()));
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
            var dstExprs = intraSolver.getOrCreateDataFlowFacts(dstVn);
            var srcExprs = intraSolver.getOrCreateDataFlowFacts(srcVn);
            for (var dstExpr : dstExprs) {
                for (var srcExpr : srcExprs) {
                    var dstSkt = exprManager.getOrCreateSkeleton(dstExpr);
                    var srcSkt = exprManager.getOrCreateSkeleton(srcExpr);

                    if (lengthVn.isConstant()) {
                        dstSkt.setComposite(true);
                        dstSkt.setSizeFromCallSite(lengthVn.getOffset(), callSite);
                        srcSkt.setComposite(true);
                        srcSkt.setSizeFromCallSite(lengthVn.getOffset(), callSite);
                        Logging.debug("ExternalHandler.Memcpy",
                                String.format("(memcpy) Set size and composite from %s -> %s with size %d", srcExpr, dstExpr, lengthVn.getOffset()));
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