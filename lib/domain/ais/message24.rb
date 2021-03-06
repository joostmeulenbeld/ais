require_relative '../vessel'

module Domain
  module AIS
    class Message24
      attr_reader :mmsi, :vessel_class, :type
      attr_accessor :vessel_type
      
      def initialize(mmsi)
        @mmsi = mmsi
        @vessel_class = Domain::Vessel::CLASS_B
        @type = 24
      end
      
      def payload
        uint = Domain::AIS::Datatypes::UInt 
        payload = ''
        
        # type
        payload << uint.bit_string(@type, 6)
        
        # repeat 
        payload << '00'
        
        # mmsi
        payload << uint.bit_string(@mmsi, 30)
        
        # part number, we only send part B
        payload << '01'
                
        # type
        if @vessel_type
          code = @vessel_type.code
        else
          code = 0  
        end
         
        payload << uint.bit_string(code, 8)
        
        # rest of message
        payload << '0' * 120
        
        payload
      end
    end
  end
end