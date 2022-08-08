use conec::{
    
    client::{StreamId, IncomingStreams},
    
    Client, ClientConfig, Coord, CoordConfig,
};

use std::{path::{PathBuf, Path}};




pub async fn Start_Judge(cert_path:&Path , key_path:&Path)-> Coord{
    let mut coord_cfg = CoordConfig::new_from_file(cert_path,key_path).unwrap();
    coord_cfg.enable_stateless_retry();
    coord_cfg.set_port(0);// auto assign
    Coord::new(coord_cfg).await.unwrap()

}
pub async fn Start_Client(cert_path:&Path ,name: String, port:u16) -> (Client, IncomingStreams){
    let mut client_cfg = ClientConfig::new(name,"localhost".to_string());
        client_cfg.set_ca_from_file(cert_path).unwrap();
        client_cfg.set_port(port);
        Client::new(client_cfg.clone()).await.unwrap()
}