package blueprint.base;

import java.util.List;
import java.util.LinkedList;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;

public class CallGraph extends GraphBase<Function> {

    /** The cache of callgraphs */
    private static final Map<Function, CallGraph> callGraphCache = new HashMap<>();

    /** The root function of the callgraph */
    private Function root;

    /**
     * Get the whole-program's call graph.
     * We did not resolve indirect calls here, and we consider each function
     * without caller as a root node of a callgraph. So the whole program may
     * contain multiple callgraphs.
     * @return the List of callgraphs
     */
    public static List<CallGraph> getWPCallGraph() {
        // TODO: Implement this method
        throw new UnsupportedOperationException("Not implemented yet");
    }

    /**
     * Get the callgraph of the given function. If the CallGraph does
     * not exist, a new one will be created.
     * @param root the root function of the callgraph
     * @return the callgraph
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
     * Create a callgraph with the given root function.
     * @param root the root function
     */
    private CallGraph(Function root) {
        this.root = root;

        LinkedList<Function> workList = new LinkedList<>();
        Set<Function> visited = new HashSet<>();

        workList.add(root);
        visited.add(root);
        while (!workList.isEmpty()) {
            Function cur = workList.remove();
            for (Function callee : cur.getCalledFunctions(TaskMonitor.DUMMY)) {
                if (visited.contains(callee)) {
                    continue;
                }
                addEdge(cur, callee);
                workList.add(callee);
                visited.add(callee);
            }
        }
    }

    @Override
    protected NodeBase<Function> createNode(Function value, int node_id) {
        return new FunctionNode(value, node_id);
    }
}
