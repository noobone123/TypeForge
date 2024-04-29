package blueprint.base.dataflow;

import blueprint.utils.Logging;

import java.util.HashSet;
import java.util.Iterator;

/**
 * KSet is a set with a maximum size.
 * If the set is full, then the add operation will return false.
 * @param <E> the element type
 */
public class KSet<E> implements Iterable<E> {
    private final HashSet<E> set;
    private final int maxSize;

    public KSet(int maxSize) {
        this.maxSize = maxSize;
        this.set = new HashSet<>();
    }

    public boolean add(E element) {
        if (set.size() >= maxSize) {
            return false;
        }
        if (set.add(element)) {
            Logging.debug("[KSet] Add element, current set: " + set);
            return true;
        } else {
            return false;
        }
    }

    public boolean contains(E element) {
        return set.contains(element);
    }

    public void merge(KSet<E> other) {
        for (E element : other.set) {
            if (this.set.size() >= this.maxSize) {
                break;
            }
            this.add(element);
        }
    }

    @Override
    public String toString() {
        return set.toString();
    }

    @Override
    public Iterator<E> iterator() {
        return set.iterator();
    }
}