use std::str::FromStr;
use serde::Deserialize;
use url::Url;
use axum::http::Uri;
use common::web_api::SignalMessages;
use common::signal_protobuf::{
    web_socket_message, WebSocketMessage, WebSocketRequestMessage, WebSocketResponseMessage
};

struct PathExtractor{
    parts: Vec<String>
}

// rust does not have variadic templates so therefore we must cope, and extract them one by one
impl PathExtractor {
    pub fn new(uri: &Uri) -> Result<Self, String> {
        let uri = uri.path();

        let mut extractor = Self {
            parts: uri.split("/").map(String::from).collect()
        };
        if extractor.parts.is_empty() {
            return Err("PathExtractor: Is empty!".to_string());
        }
        if uri.starts_with("/"){
            extractor.parts.remove(0);
        }
        Ok(extractor)
    }
    pub fn extract<T: FromStr<Err = impl std::fmt::Debug>>(&self, index: usize) -> Result<T, String>{
        if index >= self.parts.len() {
            return Err("PathExtractor: Larger than count".to_string());
        }
        match T::from_str(&self.parts[index]) {
            Ok(x) => Ok(x),
            Err(_) => Err("failed to convert".to_string())
        }
    }
}


fn create_response(id: u64, status: u32, message: &str, mut headers: Vec<String>, body: Option<Vec<u8>>) -> WebSocketMessage{
    if !headers.iter().any(|x| x.starts_with("Content-Length")){
        headers.push(format!("Content-Length: {}", body.as_ref().map(|v| v.len()).unwrap_or(0)));
    }

    let res = WebSocketResponseMessage {
        id: Some(id),
        status: Some(status),
        message: Some(message.to_string()),
        headers: headers,
        body: body
    };

    WebSocketMessage {
        r#type: Some(web_socket_message::Type::Response as i32),
        request: None,
        response: Some(res)
    }
}

fn create_request(id: u64, verb: &str, path: &str, headers: Vec<String>, body: Option<Vec<u8>>) -> WebSocketMessage{
    let req = WebSocketRequestMessage {
        verb: Some(verb.to_string()),
        path: Some(path.to_string()),
        body: body,
        headers: headers,
        id: Some(id),
    };
    WebSocketMessage {
        r#type: Some(web_socket_message::Type::Request as i32),
        request: Some(req),
        response: None
    }
}

fn unpack_messages(ws_message: WebSocketMessage) -> Result<SignalMessages, String> {
    let req =  match ws_message.r#type() {
        web_socket_message::Type::Request => {
            match ws_message.request {
                Some(x) => x,
                None => return Err("Message was not a SignalMessages".to_string())
            }
        },
        _ => return Err("Message was not a SignalMessages".to_string())
    };
    let body = match req.body {
        None => return Err("Body was none".to_string()),
        Some(x) => x
    };

    let json = match String::from_utf8(body) {
        Err(_) => return Err(format!("Failed to convert req body to string")),
        Ok(y) => y,
    };

    match serde_json::from_str(&json){
        Err(_) => return Err(format!("Failed to convert json to SignalMessages")),
        Ok(y) => Ok(y)
    }
}



#[cfg(test)]
pub(crate) mod test {
    use std::str::FromStr;

    use super::{create_request, create_response, unpack_messages, PathExtractor};
    use axum::http::Uri;
    use common::signal_protobuf::web_socket_message;


    #[test]
    fn test_path_extractor(){
        let uri = Uri::from_str("/a/b/1/true/hello").unwrap();
        let extractor = PathExtractor::new(&uri).unwrap();

        let (x, y, z) = extractor.extract::<u8>(2).and_then(|x, | {
           extractor.extract::<bool>(3).map(|y|(x, y))
        }).and_then(|(x,y)|{
            extractor.extract::<String>(4).map(|z|(x,y,z))
        }).expect("Expected that 2, 3, 4 were int, bool and string");

        assert!(x == 1);
        assert!(y);
        assert!(z == "hello");
    }

    #[test]
    fn test_create_response(){
        let msg = create_response(
            1, 
            200, 
            "OK", 
            vec!["my-header: ok".to_string()], 
            None
        );
        assert!(msg.r#type() == web_socket_message::Type::Response);
        let res = msg.response.unwrap();
        assert!(res.id() == 1);
        assert!(res.message() == "OK");
        assert!(res.status() == 200);
        assert!(res.body == None);
        assert!(res.headers[0] == "my-header: ok");
    }

    #[test]
    fn test_create_request(){
        let msg = create_request(
            1, 
            "PUT", 
            "/v1/messages", 
            vec!["my-header: ok".to_string()], 
            None);
        assert!(msg.r#type() == web_socket_message::Type::Request);
        let req = msg.request.unwrap();
        assert!(req.id() == 1);
        assert!(req.verb() == "PUT");
        assert!(req.path() == "/v1/messages");
        assert!(req.body == None);
        assert!(req.headers[0] == "my-header: ok");
    }

    #[test]
    fn test_unpack_messages(){
        let msg = r#"
{
    "messages":[
        {
            "type": 1,
            "destinationDeviceId": 3,
            "destinationRegistrationId": 22,
            "content": "aGVsbG8="
        }
    ],
    "online": false,
    "urgent": true,
    "timestamp": 1730217386
}
"#;
        let b = msg.as_bytes().to_vec();

        let req = create_request(
            1, 
            "PUT", 
            "/v1/messages",
            vec![], 
            Some(b));

        let msg = unpack_messages(req).unwrap();
        assert!(msg.online == false);
        assert!(msg.urgent);
        assert!(msg.timestamp == 1730217386);
        assert!(msg.messages[0].content == "aGVsbG8=");
        assert!(msg.messages[0].r#type == 1);
        assert!(msg.messages[0].destination_device_id == 3);
        assert!(msg.messages[0].destination_registration_id == 22);
    }
}