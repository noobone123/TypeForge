package typeforge.utils;

import ghidra.program.model.data.DataType;
import typeforge.base.dataflow.constraint.Skeleton;

import java.util.*;

public class TCHelper {
    public static class Interval {
        final long start;
        final long end;

        Interval(long start, long end) {
            this.start = start;
            this.end = end;
        }

        public boolean inInterval(long offset) {
            return offset > start && offset < end;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj instanceof Interval) {
                return this.start == ((Interval) obj).start && this.end == ((Interval) obj).end;
            }
            return false;
        }

        @Override
        public int hashCode() {
            return Objects.hash(start, end);
        }
    }

    /**
     * If a field's start in other field's interval, then return true
     * If two fields have same start, but one field's end is larger than other field's start, then return true
     * @return if overlap occurs
     */
    public static boolean checkFieldOverlapStrict(Skeleton a, Skeleton b) {
        var aIntervals = buildIntervals(a);
        var bIntervals = buildIntervals(b);
        for (var aI: aIntervals) {
            for (var bI: bIntervals) {
                if (aI.inInterval(bI.start) || bI.inInterval(aI.start)) {
                    return true;
                }

                if (aI.start == bI.start) {
                    var aNI = getNextLargerInterval(aI, aIntervals);
                    if (aNI != null && bI.end > aNI.start) {
                        return true;
                    }

                    var bNI = getNextLargerInterval(bI, bIntervals);
                    if (bNI != null && aI.end > bNI.start) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    // TODO: not very expected ... since (0,4) maybe (0,2) + (2,4), and this is still overlap
    public static boolean checkFieldOverlapRelax(Skeleton a, Skeleton b) {
        var aIntervals = buildIntervalWithMostAccessed(a);
        var bIntervals = buildIntervalWithMostAccessed(b);
        for (var aI: aIntervals) {
            for (var bI: bIntervals) {
                if (aI.inInterval(bI.start) || bI.inInterval(aI.start)) {
                    return true;
                }

                if (aI.start == bI.start) {
                    var aNI = getNextLargerInterval(aI, aIntervals);
                    if (aNI != null && bI.end > aNI.start) {
                        return true;
                    }

                    var bNI = getNextLargerInterval(bI, bIntervals);
                    if (bNI != null && aI.end > bNI.start) {
                        return true;
                    }
                }
            }
        }
        return false;
    }


//    public static boolean checkFieldSizeInConsistent(TypeConstraint a, TypeConstraint b) {
//        if (a == b) {
//            return false;
//        }
//        Set<Interval> thisIntervals = new HashSet<>();
//        for (var offset : a.fieldAccess.keySet()) {
//            long endOffset = calcFieldEndOffset(a, offset);
//            thisIntervals.add(new Interval(offset, endOffset));
//        }
//
//        Set<Interval> otherIntervals = new HashSet<>();
//        for (var offset : b.fieldAccess.keySet()) {
//            long endOffset = calcFieldEndOffset(b, offset);
//            otherIntervals.add(new Interval(offset, endOffset));
//        }
//
//        Set<Interval> commonIntervals = new HashSet<>(thisIntervals);
//        commonIntervals.retainAll(otherIntervals);
//
//        thisIntervals.removeAll(commonIntervals);
//        otherIntervals.removeAll(commonIntervals);
//
//        if (thisIntervals.isEmpty() || otherIntervals.isEmpty()) {
//            return false;
//        }
//
//        List<Interval> mergedIntervals = new ArrayList<>(thisIntervals);
//        mergedIntervals.addAll(otherIntervals);
//        mergedIntervals.sort(Comparator.comparingLong(interval -> interval.start));
//        for (int i = 0; i < mergedIntervals.size() - 1; i++) {
//            Interval current = mergedIntervals.get(i);
//            Interval next = mergedIntervals.get(i + 1);
//            if (current.end > next.start) {
//                return true;
//            }
//        }
//        return false;
//    }

    public static ArrayList<Interval> buildIntervals(Skeleton a) {
        ArrayList<Interval> intervals = new ArrayList<>();
        for (var offset : a.fieldAccess.keySet()) {
            for (var endOffset : calcFieldEndOffset(a, offset)) {
                intervals.add(new Interval(offset, endOffset));
            }
        }
        return intervals;
    }

    public static ArrayList<Interval> buildIntervalWithMostAccessed(Skeleton a) {
        ArrayList<Interval> intervals = new ArrayList<>();

        for (var offset : a.fieldAccess.keySet()) {
            var aps = a.fieldAccess.get(offset);
            if (aps == null || aps.getApSet().isEmpty()) {
                continue;
            }

            var typeFreq = aps.getTypeFreq();
            DataType mostAccessedType = null;
            int maxAccess = 0;

            for (var entry : typeFreq.entrySet()) {
                if (entry.getValue() > maxAccess) {
                    maxAccess = entry.getValue();
                    mostAccessedType = entry.getKey();
                }
            }

            if (mostAccessedType != null) {
                long endOffset = offset + mostAccessedType.getLength();
                intervals.add(new Interval(offset, endOffset));
            }
        }

        return intervals;
    }

    public static Interval getNextLargerInterval(Interval cur, List<Interval> intervals) {
        for (var interval: intervals) {
            if (interval.start >= cur.end) {
                return interval;
            }
        }
        return null;
    }


    public static Set<Long> calcFieldEndOffset(Skeleton a, Long offset) {
        Set<Long> ends = new TreeSet<>();
        var fields = a.fieldAccess.get(offset);
        if (fields == null) {
            return ends;
        }

        for (var ap : fields.getApSet()) {
            if (ap.dataType != null) {
                ends.add(offset + ap.dataType.getLength());
            }
        }
        return ends;
    }
}
