package blueprint.base;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import blueprint.base.Node;

public abstract class GraphBase<T> {

    /** Graph's id */
    protected int id = -1;

    /** Whether the graph has been changed */
    protected boolean changed = false;

    /** Map from node's value to node */
    private final Map<T, Node<T>> valueToNode = new HashMap<>();

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
    public Node<T> getNode(T value) {
        if (valueToNode.containsKey(value)) {
            return valueToNode.get(value);
        }
        Node<T> res = new Node<>(value, node_cnt);
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
        Node<T> src = getNode(from);
        Node<T> dst = getNode(to);
        if (src.succ.contains(to)) {
            changed = false;
            return;
        }
        src.succ.add(to);
        dst.pred.add(from);
        changed = true;
    }

    /**
     * Delete a graph edge with source and destination.
     * @param from the source node's value
     * @param to the destination node's value
     */
    public void deleteEdge(T from, T to) {
        Node<T> src = getNode(from);
        Node<T> dst = getNode(to);

        if (src.succ.remove(to)) {
            changed = true;
        }
        if (dst.pred.remove(from)) {
            changed = true;
        }
    }

    /**
     * Return a list of the node's successors
     * @param value the node value
     * @return Return a list of the node's successors
     */
    public List<T> getSuccs(T value) {
        Node<T> tmp = getNode(value);
        return new LinkedList<>(tmp.succ);
    }

    /**
     * Return a list of the node's predecessors
     * @param value the node value
     * @return Return a list of the node's predecessors
     */
    public List<T> getPreds(T value) {
        Node<T> tmp = getNode(value);
        return new LinkedList<>(tmp.pred);
    }

    /**
     * Check if the graph has a path from src to dst
     * @param from The src node
     * @param to The dst node
     * @return True if it has a path from src to dst
     */
    public boolean hasPath(T from, T to) {
        if (valueToNode.get(from) == null || valueToNode.get(to) == null) {
            return false;
        }

        LinkedList<T> workList = new LinkedList<>();
        Set<T> visited = new HashSet<>();
        workList.add(from);
        visited.add(to);
        while (!workList.isEmpty()) {
            T now = workList.remove();
            for (T succ : getSuccs(now)) {
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

}
