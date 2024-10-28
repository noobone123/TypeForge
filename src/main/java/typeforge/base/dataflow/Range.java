package typeforge.base.dataflow;

import java.util.Objects;
import java.util.Set;

public class Range {
    private final long start;
    private final long end;

    public Range(Long start, Long end) {
        this.start = start;
        this.end = end;
    }

    public long getStart() {
        return start;
    }

    public long getEnd() {
        return end;
    }

    static public boolean ifRangeInRanges(Range range, Set<Range> existRanges) {
        for (var r: existRanges) {
            if (range.getStart() >= r.getStart() && range.getEnd() <= r.getEnd()) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hash(start, end);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Range range = (Range) o;
        return Objects.equals(start, range.start) &&
                Objects.equals(end, range.end);
    }
}
