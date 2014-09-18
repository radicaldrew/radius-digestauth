
 function ord(string) {
      //  discuss at: http://phpjs.org/functions/ord/
      // original by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
      // bugfixed by: Onno Marsman
      // improved by: Brett Zamir (http://brett-zamir.me)
      //    input by: incidence
      //   example 1: ord('K');
      //   returns 1: 75
      //   example 2: ord('\uD800\uDC00'); // surrogate pair to create a single Unicode character
      //   returns 2: 65536
    
      var str = string + '',
        code = str.charCodeAt(0);
      if (0xD800 <= code && code <= 0xDBFF) { // High surrogate (could change last hex to 0xDB7F to treat high private surrogates as single characters)
        var hi = code;
        if (str.length === 1) {
          return code; // This is just a high surrogate with no following low surrogate, so we return its value;
          // we could also throw an error as it is not a complete character, but someone may want to know
        }
        var low = str.charCodeAt(1);
        return ((hi - 0xD800) * 0x400) + (low - 0xDC00) + 0x10000;
      }
      if (0xDC00 <= code && code <= 0xDFFF) { // Low surrogate
        return code; // This is just a low surrogate with no preceding high surrogate, so we return its value;
        // we could also throw an error as it is not a complete character, but someone may want to know
      }
      return code;
  }
  
  function A1(username,realm,password){
    return username + ":" + realm + ":" + password;
  }
  
  function A2(method,uri){
    return method + ":" + uri;
  }
  
  function H(data){
    return md5(data);
  }
  
  function KD(secret, data){
    return H(secret + ":" + data);
  }
  
  
  function parse_digest(digest_attributes){
    var supportedTypes = { 1: 'realm', 2: 'nonce',  3: 'method',  4: 'uri', 6: 'algorithm', 10: 'username'};
    var digest_array = [];
       Object.keys(digest_attributes).forEach(function(key) {
          var attr = digest_attributes[key];
            if(attr.length < 3){
                console.log('Attribute length too small: ' + attr.length + '. Should be at least 3');
            }else{
                var attrType = ord(attr[0]);
                if(attrType <= 0 || attrType > 10){
                    console.log('Invalid attribute type ' + attrType);
                }else{
                     if(supportedTypes[attrType]){
                         var attrLength = ord(attr[1]);
                         if(attrLength != attr.length){
                            console.log('Received incorrect attribute length: ' + attrLength + '. Real length is ' + attr.length);
                         }else{
                             var attrContent = attr.slice(2);
                             digest_array[supportedTypes[attrType]] = attrContent;
                         }
                     }else{
                        console.log('Invalid attribute type');
                     }      
                }
            }
            
        });
        return digest_array;
  }




module.exports = {
    parse_digest: function(digest_attributes) {
        return parse_digest(digest_attributes);
    },
    authenticate_user: function(digest_attributes, digest_response, password) {
   
      var digest_array = parse_digest(digest_attributes);
    
      var username = digest_array['username'];
      var realm = digest_array['realm'];
      var method = digest_array['method'];
      var uri = digest_array['uri'];
      var nonce = digest_array['nonce'];
      
      if(digest_response){
          var returnstr = KD(H(A1(username,realm,password)), nonce + ":" + H(A2(method,uri)));
          
          if(digest_response == returnstr){
            return true;
          }else{
            return false;
          }
      
      }else{
        return false;
      }
 
    }
};