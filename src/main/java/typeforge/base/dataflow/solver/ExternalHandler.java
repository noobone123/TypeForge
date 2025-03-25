package typeforge.base.dataflow.solver;

import typeforge.base.dataflow.expression.NMAEManager;
import typeforge.base.node.CallSite;
import typeforge.utils.Logging;

import java.util.HashMap;
import java.util.Map;

/**
 * Handler for external function calls.
 */
// TODO: Composite Type的判断：所有的memset、memcpy、malloc等函数实际上都可以用于确定composite type
// TODO: If a Const (Type: Argument) has a path to malloc/calloc's sensitive param, callsite's receiver's size should be set.
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

    /**
     * Handler for memset function
     */
    public static class Memset extends Handler {
        @Override
        public void handle(CallSite callSite, IntraSolver intraSolver, NMAEManager exprManager) {
            var lengthArg = callSite.arguments.get(2);
            if (lengthArg.isConstant()) {
                var ptrExprs = intraSolver.getDataFlowFacts(callSite.arguments.get(0));
                for (var expr: ptrExprs) {
                    exprManager.getOrCreateConstraint(expr)
                            .setSizeFromCallSite(lengthArg.getOffset(), callSite);
                    Logging.info("ExternalHandler.Memset",
                            String.format("Set size of constraint: %s to %d", expr, lengthArg.getOffset()));
                }
            }
        }
    }

    /**
     * Handler for memcpy function
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
                    if (lengthVn.isConstant()) {
                        exprManager.getOrCreateConstraint(dstExpr)
                                .setSizeFromCallSite(lengthVn.getOffset(), callSite);
                        exprManager.getOrCreateConstraint(srcExpr)
                                .setSizeFromCallSite(lengthVn.getOffset(), callSite);
                        Logging.info("ExternalHandler.Memcpy",
                                String.format("Copy from %s -> %s with size %d", srcExpr, dstExpr, lengthVn.getOffset()));
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
        // Add more handlers as needed
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