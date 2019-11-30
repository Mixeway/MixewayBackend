package io.mixeway.pojo;

public class StatisticHelper {
	
	private String name;
	private String zmdi;
	private Long number;
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getZmdi() {
		return zmdi;
	}
	public void setZmdi(String zmdi) {
		this.zmdi = zmdi;
	}
	public Long getNumber() {
		return number;
	}
	public void setNumber(Long number) {
		this.number = number;
	}
	public StatisticHelper(String name, String zmdi, Long number) {
		this.setName(name);
		this.setNumber(number);
		this.setZmdi(zmdi);
	}
	
	

}
