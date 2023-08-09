package io.mixeway.utils;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.runner.RunWith;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.ArrayList;
import java.util.List;

@RunWith(SpringRunner.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public class SomeTest {

    class Event {
        String inserted;
        String start;
        String end;
        int occurrences;
        String eventType;

        public Event(String inserted, int occurrences, String eventType) {
            this.inserted = inserted;
            this.start = inserted;
            this.end = inserted;
            this.occurrences = occurrences;
            this.eventType = eventType;
        }

        @Override
        public String toString() {
            return "{" +
                    "\"inserted\":\"" + inserted + '\"' +
                    ", \"start\":\"" + start + '\"' +
                    ", \"end\":\"" + end + '\"' +
                    ", \"occurances\":" + occurrences +
                    ", \"eventType\":\"" + eventType + '\"' +
                    '}';
        }
    }

    @Test
    public void test(){
        List<Event> events = new ArrayList<>();
        events.add(new Event("01-04-2022", 10, "CREATED"));
        events.add(new Event("01-04-2022", 10, "CREATED"));
        events.add(new Event("01-04-2022", 10, "UPDATED"));
        events.add(new Event("03-04-2022", 10, "UPDATED"));
        events.add(new Event("04-04-2022", 10, "UPDATED"));
        events.add(new Event("06-04-2022", 10, "RESOLVED"));
        events.add(new Event("07-04-2022", 10, "CREATED"));
        events.add(new Event("08-04-2022", 10, "RESOLVED"));

        List<Event> mergedEvents = mergeEvents(events);

        for (Event e : mergedEvents) {
            System.out.println(e);
        }
    }
    public List<Event> mergeEvents(List<Event> events) {
        List<Event> result = new ArrayList<>();
        Event currentEvent = null;

        for (Event event : events) {
            if (currentEvent == null || !currentEvent.eventType.equals(event.eventType)) {
                if (currentEvent != null) {
                    result.add(currentEvent);
                }
                currentEvent = new Event(event.inserted, event.occurrences, event.eventType);
            } else {
                currentEvent.occurrences += event.occurrences;
                currentEvent.end = event.inserted;
            }
        }

        if (currentEvent != null) {
            result.add(currentEvent);
        }

        return result;
    }
}
