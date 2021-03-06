
module VesselComplianceSteps
  def self.create_vessel(i, name, speed, anchored)
    vessel = Domain::Vessel.new(1_000 + i, Domain::Vessel::CLASS_A)
    vessel.name = name
    vessel.speed = speed.to_f 
    vessel.anchored = true
    vessel.heading = 19.9 * i.to_f
    vessel.position = Domain::LatLon.new(51.81 + (i.to_f / 50.0), 4.1 + (i.to_f / 20.0))
    vessel    
  end
  
  def self.send_first_report(info, report_type, registry)
    timestamps = {}
    info.each do |vessel,interval|
      timestamp = Time.new.to_f - interval + 1
      registry.bind('ais/transmitter') do |service|
        service.send_position_report_for(vessel, timestamp)
      end
      if report_type == 'static'
        registry.bind('ais/transmitter') do |service|
          service.send_static_report_for(vessel, timestamp)
        end
      end
      timestamps[vessel.mmsi] = timestamp
    end  
    timestamps
  end
end

Given /^anchored class "(.*?)" vessels with dynamic information:$/ do |class_str, table|
  class_str.should eq('A')

  @vessels = {}
  table.rows_hash.each do |name,speed|
    next if name == 'name'
    @vessels[name] = VesselComplianceSteps::create_vessel(@vessels.length, name, speed, true)
    @vessels[name].navigation_status = Domain::NavigationStatus.from_str('Anchored')
  end
end

Given /^non\-anchored class "(.*?)" vessels with dynamic information:$/ do |class_str, table|
  class_str.should eq('A')
  
  @vessels = {}
  table.rows_hash.each do |name,speed|
    next if name == 'name'
    @vessels[name] = VesselComplianceSteps::create_vessel(@vessels.length, name, speed, false)
  end
end

Given /^class "(.*?)" vessels with a changing course and dynamic information:$/ do |class_str, table|
  class_str.should eq('A')
  
  @vessels = {}
  @changing_course = {}
  table.rows_hash.each do |name,speed|
    next if name == 'name'
    @changing_course[name] = true
    @vessels[name] = VesselComplianceSteps::create_vessel(@vessels.length, name, speed, false)
  end
end

Given /^class "(.*?)" vessels:$/ do |class_str, table|
  class_str.should eq('A')

  @vessels = {}
  table.raw.flatten.each do |name|
    next if name == 'name'
    @vessels[name] = VesselComplianceSteps::create_vessel(@vessels.length, name, 10.0, false)
  end
end

When /^these vessels send a position report$/ do
  @last_report = 'dynamic'
end

When /^send another position report after:$/ do |table|
  # Gather info
  info = []
  table.rows_hash.each do |name,interval_str|
    next if name == 'name'
    raise "Vessel '#{name}' not known" unless @vessels.has_key?(name)
    
    vessel = @vessels[name]
    interval = interval_str.to_f
    info << [vessel, interval]
  end
   
  
  # First message
  timestamps = VesselComplianceSteps::send_first_report(info, @last_report, @registry)

  # Second message
  info.each do |vessel,interval|
    if @changing_course and @changing_course.has_key?(vessel.name)
      vessel.heading += 19.9
    end

    @registry.bind('ais/transmitter') do |service|
      service.send_position_report_for(vessel, timestamps[vessel.mmsi] + interval)
    end
  end  
  sleep(1)    
end

When /^these vessels send a static report$/ do
  @last_report = 'static'
end

When /^send another static report after:$/ do |table|
  
  # Gather info
  info = []
  table.rows_hash.each do |name,interval_str|
    next if name == 'name'
    raise "Vessel '#{name}' not known" unless @vessels.has_key?(name)
    
    vessel = @vessels[name]
    interval = interval_str.to_f
    info << [vessel, interval]
  end
   
  
  # First message
  timestamps = VesselComplianceSteps::send_first_report(info, @last_report, @registry)

  # Second message
  info.each do |vessel,interval|
    @registry.bind('ais/transmitter') do |service|
      service.send_static_report_for(vessel, timestamps[vessel.mmsi] + interval)
    end
  end  
  sleep(1)
end

Then /^the compliance of the vessels should be marked as:$/ do |table|
  visit map_path
  table.rows_hash.each do |name,compliant|
    next if name == 'name'
    raise "Vessel '#{name}' not known" unless @vessels.has_key?(name)
    position = @vessels[name].position
    
    args = [position.lat, position.lon]
    js = "map.hasMarkerAt(new LatLon(%f,%f))" % args
    marked = page.evaluate_script(js)
    if not marked
      raise "No marker for vessel #{name} found at position #{position}"
    end
    
    args = [position.lat, position.lon, 'red']
    js = "map.hasMarkerAt(new LatLon(%f,%f), '%s')" % args
    marked_as_compliant = (not page.evaluate_script(js))
    
    if compliant == 'yes' and not marked_as_compliant
      raise "Vessel #{name} is compliant, yet is shown as non-compliant"
    elsif compliant == 'no' and marked_as_compliant
      raise "Vessel #{name} is not compliant, yet is shown as compliant"
    end
  end
end
