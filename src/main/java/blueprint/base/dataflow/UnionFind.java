package blueprint.base.dataflow;

import java.util.Map;
import java.util.HashMap;

public class UnionFind<T> {
    private final Map<T, T> parent = new HashMap<>();
    private final Map<T, Integer> rank = new HashMap<>();

    private void ensureSet(T element) {
        if (!parent.containsKey(element)) {
            parent.put(element, element);
            rank.put(element, 0);
        }
    }

    public T find(T s) {
        ensureSet(s);
        if (parent.get(s) != s) {
            parent.put(s, find(parent.get(s)));
        }
        return parent.get(s);
    }

    public void union(T x, T y) {
        ensureSet(x);
        ensureSet(y);

        T xRoot = find(x);
        T yRoot = find(y);

        if (xRoot == yRoot) {
            return;
        }
        if (rank.get(xRoot) < rank.get(yRoot)) {
            parent.put(xRoot, yRoot);
        } else if (rank.get(xRoot) > rank.get(yRoot)) {
            parent.put(yRoot, xRoot);
        } else {
            parent.put(yRoot, xRoot);
            rank.put(xRoot, rank.get(xRoot) + 1);
        }
    }
}
