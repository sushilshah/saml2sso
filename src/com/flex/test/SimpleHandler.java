package com.flex.test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

public class SimpleHandler extends DefaultHandler {

    class Employee {
        public String firstName;
        public String lastName;
        public String location;
        public Map<String, String> attributes = new HashMap<>();
    }
    boolean isFirstName, isLastName, isLocation;
    Employee currentEmployee;
    List<Employee> employees = new ArrayList<>();

    @Override
    public void startElement(String uri, String localName, String qName,
            Attributes atts) throws SAXException {
        if(qName.equals("employee")) {
            currentEmployee = new Employee();
            for(int i = 0; i < atts.getLength(); i++) {
                currentEmployee.attributes.put(atts.getQName(i),atts.getValue(i));
            }
        }
        if(qName.equals("firstName")) { isFirstName = true; }
        if(qName.equals("lastName"))  { isLastName = true;  }
        if(qName.equals("location"))  { isLocation = true;  }
    }

    @Override
    public void endElement(String uri, String localName, String qName)
            throws SAXException {
        if(qName.equals("employee")) {
            employees.add(currentEmployee);
            currentEmployee = null;
        }
        if(qName.equals("firstName")) { isFirstName = false; }
        if(qName.equals("lastName"))  { isLastName = false;  }
        if(qName.equals("location"))  { isLocation = false;  }
    }

    @Override
    public void characters(char[] ch, int start, int length) throws SAXException {
        if (isFirstName) {
            currentEmployee.firstName = new String(ch, start, length);
        }
        if (isLastName) {
            currentEmployee.lastName = new String(ch, start, length);
        }
        if (isLocation) {
            currentEmployee.location = new String(ch, start, length);
        }
    }

    @Override
    public void endDocument() throws SAXException {
        for(Employee e: employees) {
            System.out.println("Employee ID: " + e.attributes.get("id"));
            System.out.println("  First Name: " + e.firstName);
            System.out.println("  Last Name: " + e.lastName);
            System.out.println("  Location: " + e.location);
        }
    }
}
