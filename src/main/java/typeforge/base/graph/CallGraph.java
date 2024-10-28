package typeforge.base.graph;

import typeforge.base.node.FunctionNode;
import typeforge.base.node.NodeBase;
import typeforge.utils.DecompilerHelper;
import typeforge.utils.Global;
import typeforge.utils.FunctionHelper;
import typeforge.utils.Logging;

import java.util.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.task.TaskMonitor;

public class CallGraph extends GraphBase<Function> {
    /** The cache of function nodes */
    public final Set<FunctionNode> functionNodes = new HashSet<>();

    /** The cache of root nodes to nodes */
    public final Map<Function, Set<Function>> rootToNodes = new HashMap<>();

    /** The cache of address to node */
    public final Map<Address, FunctionNode> addrToNode = new HashMap<>();

    /** Possible root nodes of the call graph */
    public Set<Function> roots;

    public Set<FunctionNode> leafNodes = new HashSet<>();

    /**
     * Get the Whole Program's call graph.
     * We did not resolve indirect calls here, and we consider each function
     * without caller as a root node of a call graph. So the whole program may
     * contain multiple root nodes in the call graph.
     * @return the Set of CallGraph
     */
    public static CallGraph getCallGraph() {
        Set<Function> possibleRoots = new HashSet<>();

        for (var func : Global.currentProgram.getListing().getFunctions(true)) {
            // These functions should not be seen as nodes of a call graph
            if (!FunctionHelper.isMeaningfulFunction(func)) {
                continue;
            }

            // If the function does not have caller or the function is 'main' function.
            // it is one root node of Whole-program's call graph
            // WARNING: ghidra's getCallingFunctions() may not work correctly, so we need to
            //          check and complete the call graph manually.
            if (func.getCallingFunctions(TaskMonitor.DUMMY).isEmpty() || FunctionHelper.isMainFunction(func)) {
                possibleRoots.add(func);
            } else if (FunctionHelper.confirmNoDirectCaller(func)) {
                possibleRoots.add(func);
            }
        }

        Logging.info("CallGraph", String.format(
                "Found %d possible root nodes of the call graph",
                possibleRoots.size()
        ));
        Logging.info("CallGraph", possibleRoots.toString());

        return new CallGraph(possibleRoots);
    }

    /**
     * Decompile each function and get high function in CallGraph.
     * Finally, build the highFunctionCache.
     */
    public void decompileAllFunctions() {
        DecompInterface ifc = DecompilerHelper.setUpDecompiler(null);
        try {
            if (!ifc.openProgram(Global.currentProgram)) {
                Logging.error("CallGraph", "Failed to use the decompiler");
                return;
            }

            for (var funcNode : functionNodes) {
                Function func = funcNode.value;
                HighFunction highFunc = null;
                DecompileResults decompileRes = ifc.decompileFunction(func, 30, TaskMonitor.DUMMY);
                if (!decompileRes.decompileCompleted()) {
                    Logging.error("CallGraph", "Decompile failed for function " + func.getName());
                    continue;
                } else {
                    Logging.info("CallGraph", "Decompile function " + func.getName());
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
     * @param possibleRoots the possible root nodes of the call graph
     */
    private CallGraph(Set<Function> possibleRoots) {
        roots = new HashSet<>(possibleRoots);

        for (Function root : roots) {
            buildCallGraph(root);
        }


        // Update FunctionNode's property
        for (var funcNode : functionNodes) {
            if (funcNode.succ.isEmpty()) {
                funcNode.isLeaf = true;
                leafNodes.add(funcNode);
            }

            if (FunctionHelper.isMeaningfulFunction(funcNode.value)) {
                funcNode.isMeaningful = true;
            }

            if (FunctionHelper.isNormalFunction(funcNode.value)) {
                funcNode.isNormal = true;
            }

            if (funcNode.value.isExternal() || funcNode.value.isThunk()) {
                funcNode.isExternal = true;
            }

            addrToNode.put(funcNode.value.getEntryPoint(), funcNode);
        }
    }


    /**
     * Build the call graph with the given root function.
     * @param root the root function of the call graph
     */
    public void buildCallGraph(Function root) {
        LinkedList<Function> workList = new LinkedList<>();
        Set<Function> visited = new HashSet<>();
        var currentProgram = Global.currentProgram;

        workList.add(root);
        visited.add(root);

        while (!workList.isEmpty()) {
            Function cur = workList.remove();
            var funcInsts = currentProgram.getListing().getInstructions(cur.getBody(), true);
            boolean hasIndirectCallee = false;
            for (var inst : funcInsts) {
                if (inst.getMnemonicString().equals("CALL")) {
                    // If Call instruction is indirect that can't be resolved, flows will be empty
                    var instFlows = inst.getFlows();
                    if (instFlows.length >= 1) {
                        hasIndirectCallee = true;
                        for (var flow : instFlows) {
                            Function calledFunc = currentProgram.getFunctionManager().getFunctionAt(flow);
                            if (calledFunc != null) {
                                addEdge(cur, calledFunc);
                                if (!visited.contains(calledFunc)) {
                                    visited.add(calledFunc);
                                    if (FunctionHelper.isMeaningfulFunction(calledFunc)) {
                                        workList.add(calledFunc);
                                    }
                                }
                            } else {
                                Logging.error("CallGraph", "Function not found at " + flow);
                            }
                        }
                    } else {
                        Logging.debug("CallGraph", "Indirect call at " + inst.getAddress());
                    }
                }
            }

            if (!hasIndirectCallee) {
                getNode(cur);
                visited.add(cur);
            }
        }
        rootToNodes.put(root, visited);
    }


    @Override
    protected NodeBase<Function> createNode(Function value, int node_id) {
        FunctionNode funcNode = new FunctionNode(value, node_id);
        functionNodes.add(funcNode);
        return funcNode;
    }

    @Override
    public FunctionNode getNode(Function value) {
        return (FunctionNode) super.getNode(value);
    }

    public FunctionNode getNodebyAddr(Address addr) {
        return addrToNode.get(addr);
    }

    public Set<FunctionNode> getCallees(FunctionNode caller) {
        Set<FunctionNode> res = new HashSet<>();
        for (var callee : caller.succ) {
            res.add((FunctionNode)callee);
        }
        return res;
    }

    public Set<FunctionNode> getCallers(FunctionNode callee) {
        Set<FunctionNode> res = new HashSet<>();
        for (var caller : callee.pred) {
            res.add((FunctionNode)caller);
        }
        return res;
    }
}
