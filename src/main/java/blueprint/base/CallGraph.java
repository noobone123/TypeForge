package blueprint.base;

import blueprint.utils.GlobalState;
import blueprint.utils.FunctionHelper;
import blueprint.utils.Logging;

import java.util.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.task.TaskMonitor;

public class CallGraph extends GraphBase<Function> {

    /** The cache of call graphs */
    private static final Map<Function, CallGraph> callGraphCache = new HashMap<>();

    /** The cache of decompiled high functions */
    private static final Map<Function, HighFunction> highFunctionCache = new HashMap<>();

    /** The root function of the call graph */
    public Function root;
    public FunctionNode rootNode;

    /** The number of functions which are not external and not thunk */
    public int normalFunctionCount = 0;

    /**
     * Get the Whole Program's call graph.
     * We did not resolve indirect calls here, and we consider each function
     * without caller as a root node of a call graph. So the whole program may
     * contain multiple call graphs.
     * @return the Set of CallGraph
     */
    public static Set<CallGraph> getWPCallGraph() {
        Set<CallGraph> callGraphs = new HashSet<>();

        for (var func : GlobalState.currentProgram.getListing().getFunctions(true)) {
            // These functions should not be seen as root nodes of a call graph
            if (!FunctionHelper.isNormalFunction(func) || FunctionHelper.isTrivialFunction(func)) {
                continue;
            }

            // callGraphCache's key is the root function
            if (callGraphCache.containsKey(func)) {
                callGraphs.add(callGraphCache.get(func));
            } else {
                // If the function does not have caller, it is a root node of a call graph
                // WARNING: ghidra's getCallingFunctions() may not work correctly, so we need to
                //          check and complete the call graph manually.
                if (func.getCallingFunctions(TaskMonitor.DUMMY).isEmpty() || FunctionHelper.isMainFunction(func)) {
                    CallGraph cg = getCallGraph(func);
                    callGraphs.add(cg);
                }
            }
        }

        Set<Function> newRoots = checkAndCompleteRootNodes();
        Logging.warn("New root nodes found: " + newRoots.size());
        for (var root : newRoots) {
            CallGraph cg = getCallGraph(root);
            callGraphs.add(cg);
        }

        return callGraphs;
    }

    /**
     * Get the call graph of the given function. If the CallGraph does
     * not exist, a new one will be created.
     * @param root the root function of the call graph's entry
     * @return the CallGraph
     */
    public static CallGraph getCallGraph(Function root) {
        if (callGraphCache.containsKey(root)) {
            return callGraphCache.get(root);
        }
        CallGraph cg = new CallGraph(root);
        callGraphCache.put(root, cg);
        return cg;
    }

    /**
     * This is a stupid function, but we have to do this.
     * Because ghidra's `getCallingFunctions()` and `getCalledFunctions()` may not work correctly.
     * For Example:
     * If function B is not called by function A, but function B's ptr is used in function A, then ghidra will
     * consider function A as a caller of function B when using `getCallingFunctions()` methods. And consider
     * function B as a callee of function A when using `getCalledFunctions()` methods.
     * <p>
     * So some function can be seen as a root node, but failed to pass the check of `getCallingFunctions().isEmpty()`.
     * We need to check and complete these root nodes.
     *
     * @return the set of root nodes which are checked and completed
     */
    public static Set<Function> checkAndCompleteRootNodes() {
        Set<Function> unvisited = new HashSet<>();
        Set<Function> result;
        Set<String> allNormalFunctionsInCG = new HashSet<>();
        boolean isChecked = false;

        for (var cg : callGraphCache.values()) {
            for (var node : cg.getAllNodes()) {
                if (FunctionHelper.isNormalFunction(node.value) && !FunctionHelper.isTrivialFunction(node.value)) {
                    allNormalFunctionsInCG.add(node.value.getName());
                }
            }
        }

        for (var func : GlobalState.currentProgram.getListing().getFunctions(true)) {
            if (!FunctionHelper.isNormalFunction(func) || FunctionHelper.isTrivialFunction(func)) {
                continue;
            }
            if (!allNormalFunctionsInCG.contains(func.getName())) {
                unvisited.add(func);
            }
        }

        // Deep copy the unvisited set
        result = new HashSet<>(unvisited);

        for (var func : unvisited) {
            isChecked = false;
            for (var caller : func.getCallingFunctions(TaskMonitor.DUMMY)) {
                var funcInsts = GlobalState.currentProgram.getListing().getInstructions(caller.getBody(), true);
                for (var inst : funcInsts) {
                    if (inst.getMnemonicString().equals("CALL")) {
                        var instFlows = inst.getFlows();
                        if (instFlows.length >= 1) {
                            for (var flow : instFlows) {
                                Function calledFunc = GlobalState.currentProgram.getFunctionManager().getFunctionAt(flow);
                                if (calledFunc != null && calledFunc.equals(func)) {
                                    result.remove(func);
                                    isChecked = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                if (isChecked) {
                    break;
                }
            }
        }

        return result;
    }

    /**
     * Decompile each function and get high function in CallGraph.
     * Finally, build the highFunctionCache.
     */
    public static void decompileAllFunctions() {
        DecompInterface ifc = FunctionHelper.setUpDecompiler(null);
        try {
            if (!ifc.openProgram(GlobalState.currentProgram)) {
                Logging.error("Failed to use the decompiler");
                return;
            }

            for (var cg : callGraphCache.values()) {
                for (var node : cg.getAllNodes()) {
                    FunctionNode funcNode = (FunctionNode) node;
                    Function func = funcNode.value;
                    if (!highFunctionCache.containsKey(func)) {
                        DecompileResults decompileRes = ifc.decompileFunction(func, 30, TaskMonitor.DUMMY);
                        if (!decompileRes.decompileCompleted()) {
                            Logging.error("Decompile failed for function " + func.getName());
                        } else {
                            HighFunction highFunc = decompileRes.getHighFunction();
                            highFunctionCache.put(func, highFunc);
                            Logging.info("Decompile function " + func.getName());
                        }
                    }
                    funcNode.setHighFunction(highFunctionCache.get(func));
                }
            }
        } finally {
            ifc.dispose();
        }
    }


    /**
     * Create a call graph with the given root function.
     * We did not use ghidra's `getCalledFunctions()` api here to build the call graph,
     * because they may not work correctly.
     * @param root the root function
     */
    private CallGraph(Function root) {
        this.root = root;
        this.rootNode = (FunctionNode) getNode(root);
        if (FunctionHelper.isNormalFunction(root)) {
            normalFunctionCount++;
        }

        var currentProgram = GlobalState.currentProgram;

        LinkedList<Function> workList = new LinkedList<>();
        Set<Function> visited = new HashSet<>();

        workList.add(root);
        visited.add(root);

        while (!workList.isEmpty()) {
            Function cur = workList.remove();
            var funcInsts = currentProgram.getListing().getInstructions(cur.getBody(), true);
            for (var inst : funcInsts) {
                if (inst.getMnemonicString().equals("CALL")) {
                    // If Call instruction is indirect that can't be resolved, flows will be empty
                    var instFlows = inst.getFlows();
                    if (instFlows.length >= 1) {
                        for (var flow : instFlows) {
                            Function calledFunc = currentProgram.getFunctionManager().getFunctionAt(flow);
                            if (calledFunc != null) {
                                addEdge(cur, calledFunc);
                                if (!visited.contains(calledFunc) && FunctionHelper.isNormalFunction(calledFunc)) {
                                    workList.add(calledFunc);
                                    visited.add(calledFunc);
                                    normalFunctionCount++;
                                }
                            } else {
                                Logging.error("Function not found at " + flow);
                            }
                        }
                    } else {
                        Logging.debug("Indirect call at " + inst.getAddress());
                    }
                }
            }
        }
    }

    @Override
    protected NodeBase<Function> createNode(Function value, int node_id) {
        return new FunctionNode(value, node_id);
    }
}
