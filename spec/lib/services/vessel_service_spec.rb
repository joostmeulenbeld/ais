require 'spec_helper'
require 'ffi-rzmq'

module Service
  describe VesselService do
    it_behaves_like "a service"
    it_behaves_like "a reply service"
    
    before(:each) do
      @registry = MockRegistry.new
      @registry.register('ais/message', 'tcp://localhost:21002')
      decoder = double('Service')
      decoder.stub(:decode) do |payload|
        Domain::AIS::SixBitEncoding.decode(payload)
      end
      @registry.stub(:bind).and_return(decoder)
      
      @vessel1 = Domain::Vessel.new(1234, Domain::Vessel::CLASS_A)
      @vessel1.position = Domain::LatLon.new(3.0, 5.0) 
      @vessel2 = Domain::Vessel.new(5678, Domain::Vessel::CLASS_A)
      @vessel2.position = Domain::LatLon.new(3.0, 4.0)
      @vessel3 = Domain::Vessel.new(9012, Domain::Vessel::CLASS_B)
      @vessel3.position = Domain::LatLon.new(2.0, 4.0) 
      
      @timestamp = "%0.9f" % Time.new.to_f
    end
    
    it "returns a list of vessels" do
      service = VesselService.new(@registry)
      service.receiveVessel(@vessel1)
      service.receiveVessel(@vessel2)

      vessels = Marshal.load(service.process_request('LIST'))
      vessels.length.should eq(2)
    end

    it "returns a filtered list of vessels when provided with an area" do
      service = VesselService.new(@registry)
      service.receiveVessel(@vessel1)
      service.receiveVessel(@vessel2)
      service.receiveVessel(@vessel3)
      
      latlons = Marshal.dump([Domain::LatLon.new(2.5, 4.5), Domain::LatLon.new(3.5, 3.5)]) 
      vessels = Marshal.load(service.process_request('LIST ' + latlons))
      vessels.length.should eq(1)
      vessels[0].mmsi.should eq(5678)
    end
    
    it "returns vessel info for a single vessel" do
      service = VesselService.new(@registry)
      service.receiveVessel(@vessel3)      
      vessel = Marshal.load(service.process_request('INFO 9012'))
      vessel.should eq(@vessel3)
    end
    
    it "listens for AIS messages reports" do
      raw = {1 => "13`wgT0P5fPGmDfN>o?TN?vN2<05",
             2 => "23`wgT0P5fPGmDfN>o?TN?vN2<05",
             3 => "33`wgT0P5fPGmDfN>o?TN?vN2<05",
             5 => "53u=:PP00001<H?G7OI0ThuB37G61<F22222220j1042240Ht2P00000000000000000008",
             18 => "B6:ChG0001v=3fRoEMlmwwlTkP06",
             19 => "C69rr800021pib3C9b19KwkRVbB>2L>@b2L42O1U0@2NK0L:1RP7",
             24 => "H44?BB4lDB1>C1CEC130001@F270"}

      ctx = ZMQ::Context.new
      sock = ctx.socket(ZMQ::PUB)
      begin
        rc = sock.bind('tcp://*:21012')
        ZMQ::Util.resultcode_ok?(rc).should be_true
        @registry.register('ais/message', 'tcp://localhost:21012')
        
        service = (Class.new(VesselService) do
          attr_reader :received_data
          def process_message(data)
            @received_data = data
          end
        end).new(@registry)

        service.start('tcp://localhost:23000')
        raw.each do |type,data|
          sock.send_string("%d %s %s" % [type, @timestamp, data])

          # Give service time to receive and process message
          sleep(0.1)
          service.received_data.should eq("%d %s %s" % [type, @timestamp, data])  
        end
        service.stop
      ensure
        sock.close
      end
    end

    it "listens for compliance reports" do
      raw = ["NON-COMPLIANT 12345", "NON-COMPLIANT 67890"]

      ctx = ZMQ::Context.new
      sock = ctx.socket(ZMQ::PUB)
      begin
        rc = sock.bind('tcp://*:21015')
        ZMQ::Util.resultcode_ok?(rc).should be_true
        @registry.register('ais/compliance', 'tcp://localhost:21015')
        
        service = (Class.new(VesselService) do
          attr_reader :received_data
          def process_compliance_report(data)
            @received_data = data
          end
        end).new(@registry)

        service.start('tcp://localhost:23001')
        raw.each do |data|
          sock.send_string(data)

          # Give service time to receive and process message
          sleep(0.1)
          service.received_data.should eq(data)  
        end
        service.stop
      ensure
        sock.close
      end
    end
    
    it "processes incoming AIS messages into vessel information" do
      # Send position report
      message = "1 #{@timestamp} 13`wgT0P5fPGmDfN>o?TN2NN2<05"
      vessel = Domain::Vessel.new(244314000, Domain::Vessel::CLASS_A)
      vessel.speed = 36.6
      vessel.heading = 79
      vessel.navigation_status = Domain::NavigationStatus.from_str("Underway using engine")

      service = VesselService.new(@registry)
      service.stub(:receiveVessel) do |v|
        if v.mmsi != vessel.mmsi or v.speed != vessel.speed or
           v.heading != vessel.heading or 
           v.navigation_status != vessel.navigation_status
          raise "Properties of vessel not as expected"
        end 
      end
      service.should_receive(:receiveVessel)
      service.process_message(message)
      
      vessel = Domain::Vessel.new(265505410, Domain::Vessel::CLASS_A)
      vessel.type = Domain::VesselType.new(50)
      message = "5 #{@timestamp} 53u=:PP00001<H?G7OI0ThuB37G61<F22222220j1042240Ht2P00000000000000000008"

      service = VesselService.new(@registry)
      service.stub(:receiveVessel) do |v|
        if v.mmsi != vessel.mmsi or v.type != vessel.type
          raise "Properties of vessel not as expected"
        end 
      end
      
      service.should_receive(:receiveVessel)
      service.process_message(message)
    end

    it "don't processes invalid AIS messages" do
      message = "1 #{@timestamp} 13`wgT0P5fPGmDfN>"

      # Send position report
      service = VesselService.new(@registry)
      service.should_not_receive(:receiveVessel)
      service.process_message(message)      
    end
    
    it "updates the existing vessel when the position of a known vessel is reported" do
      vessel1 = Domain::Vessel.new(1234, Domain::Vessel::CLASS_A)
      vessel1.position = Domain::LatLon.new(3.0, 4.0) 
      vessel2 = Domain::Vessel.new(1234, Domain::Vessel::CLASS_A)
      vessel2.position = Domain::LatLon.new(5.0, 6.0)

      # Send the messages
      service = VesselService.new(@registry)
      service.receiveVessel(vessel1)
      service.receiveVessel(vessel2)
      
      # Only one vessel should be reported, and with the latest
      # position
      vessels = Marshal.load(service.process_request('LIST'))
      vessels.length.should eq(1)
      vessels[0].position.lat.should be_within(0.01).of(5.0)
      vessels[0].position.lon.should be_within(0.01).of(6.0)
    end
    
    it "adds a vessels that are not known yet" do
      vessel1 = Domain::Vessel.new(1234, Domain::Vessel::CLASS_A)
      vessel1.position = Domain::LatLon.new(3.0, 4.0) 
      vessel2 = Domain::Vessel.new(5678, Domain::Vessel::CLASS_A)
      vessel2.position = Domain::LatLon.new(5.0, 6.0)
      
      service = VesselService.new(@registry)
      service.receiveVessel(vessel1)
      service.receiveVessel(vessel2)
      vessels = service.process_request('LIST')
      vessels.should eq(Marshal.dump([vessel1, vessel2]))
    end
    
    describe "process_compliance_report" do
      it "marks reported vessels as non-compliant" do
        vessel = Domain::Vessel.new(1234, Domain::Vessel::CLASS_A)
        vessel.position = Domain::LatLon.new(3.0, 4.0) 
      
        service = VesselService.new(@registry)
        service.receiveVessel(vessel)
        service.process_compliance_report("NON-COMPLIANT 1234")
        returned_vessel = Marshal.load(service.process_request('INFO 1234'))
        returned_vessel.compliant.should be_false
      end

      it "ignores reports for unknown vessels" do
        # First send report
        service = VesselService.new(@registry)
        service.process_compliance_report("NON-COMPLIANT 1234")

        # Only then add the vessel
        vessel = Domain::Vessel.new(1234, Domain::Vessel::CLASS_A)
        vessel.position = Domain::LatLon.new(3.0, 4.0) 
        service.receiveVessel(vessel)
        
        returned_vessel = Marshal.load(service.process_request('INFO 1234'))
        returned_vessel.compliant.should be_true
      end
    end
  end
end