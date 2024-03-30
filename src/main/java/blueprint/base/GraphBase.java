package blueprint.base;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.listing.Function;
import org.w3c.dom.Node;

public abstract class GraphBase<T> {

    /** Graph's id */
    protected int id = -1;

    /** Whether the graph has been changed */
    protected boolean changed = false;

    /** Map from node's value to node */
    private final Map<T, NodeBase<T>> valueToNode = new HashMap<>();

    /** Map from node's id to node's value */
    protected final Map<Integer, T> idToValueMap = new HashMap<>();

    /** Map from node's value to node's id */
    protected final Map<T, Integer> valueToIdMap = new HashMap<>();

    /** Number of nodes in the graph */
    protected int node_cnt = 0;

    /**
     * An array of integers, where the indexes represent the id of each node and
     * the values are the depth-first numbering.
     */
    protected int[] depthFirstNums = null;

    /**
     * Get a Node for the given value from the graph.
     * This may create a new node if needed.
     * @param value The node's value
     * @return the graph node.
     */
    public NodeBase<T> getNode(T value) {
        if (valueToNode.containsKey(value)) {
            return valueToNode.get(value);
        }

        NodeBase<T> res = createNode(value, node_cnt);

        valueToNode.put(value, res);
        idToValueMap.put(node_cnt, value);
        valueToIdMap.put(value, node_cnt);
        node_cnt++;
        changed = true;
        return res;
    }

    /**
     * Create a graph edge with source and destination.
     * This also creates the graph node of the given parameters if needed.
     * @param from the source node's value
     * @param to the destination node's value
     */
    public void addEdge(T from, T to) {
        NodeBase<T> src = getNode(from);
        NodeBase<T> dst = getNode(to);
        if (src.succ.contains(dst)) {
            changed = false;
            return;
        }
        src.succ.add(dst);
        dst.pred.add(src);
        changed = true;
    }

    /**
     * Delete a graph edge with source and destination.
     * @param from the source node's value
     * @param to the destination node's value
     */
    public void deleteEdge(T from, T to) {
        NodeBase<T> src = getNode(from);
        NodeBase<T> dst = getNode(to);

        if (src.succ.remove(dst)) {
            changed = true;
        }
        if (dst.pred.remove(src)) {
            changed = true;
        }
    }

    /**
     * Return a list of the value's successors
     * @param value the node value
     * @return Return a list of the value's successors
     */
    public Set<T> getSuccs(T value) {
        NodeBase<T> tmp = getNode(value);
        Set<T> res = new HashSet<>();
        for (NodeBase<T> node : tmp.succ) {
            res.add(node.value);
        }
        return res;
    }

    /**
     * Return a list of the node's successors
     * @param node the node
     * @return Return a list of the node's successors
     */
    public Set<NodeBase<T>> getSuccNodes(NodeBase<T> node) {
        return node.succ;
    }

    /**
     * Return a list of the value's predecessors
     * @param value the node value
     * @return Return a list of the value's predecessors
     */
    public Set<T> getPreds(T value) {
        NodeBase<T> tmp = getNode(value);
        Set<T> res = new HashSet<>();
        for (NodeBase<T> node : tmp.pred) {
            res.add(node.value);
        }
        return res;
    }

    /**
     * Return a list of the node's predecessors
     * @param node the node
     * @return Return a list of the node's predecessors
     */
    public Set<NodeBase<T>> getPredNodes(NodeBase<T> node) {
        return node.pred;
    }

    /**
     * Check if the graph has a path from src to dst
     * @param from The src node
     * @param to The dst node
     * @return True if it has a path from src to dst
     */
    public boolean hasPath(T from, T to) {
        NodeBase<T> src = getNode(from);
        NodeBase<T> dst = getNode(to);
        if (src == null || dst == null) {
            return false;
        }

        LinkedList<NodeBase<T>> workList = new LinkedList<>();
        Set<NodeBase<T>> visited = new HashSet<>();
        workList.add(src);
        visited.add(dst);
        while (!workList.isEmpty()) {
            var cur = workList.remove();
            for (var succ : getSuccNodes(cur)) {
                if (succ == to) {
                    return true;
                }
                if (visited.contains(succ)) {
                    continue;
                }
                visited.add(succ);
                workList.add(succ);
            }
        }
        return false;
    }


    /**
     * Create a graph node with the given value.
     * @param value the node's value
     * @return the graph node
     */
    protected abstract NodeBase<T> createNode(T value, int node_id);
}
