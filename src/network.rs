use bytes::Bytes;
use conec::{
    
    client::{ IncomingStreams},
    
    Client, ClientConfig, Coord, CoordConfig,
};
use futures::{SinkExt, TryStreamExt, StreamExt, };
use subtle::Choice;

use std::{path::{ Path},};
use tokio_util::codec::{FramedWrite,FramedRead,length_delimited::LengthDelimitedCodec};
use quinn::{SendStream,RecvStream};

#[allow(non_camel_case_types)]

pub struct Comm_Channel {
    s12:FramedWrite<SendStream,LengthDelimitedCodec>,
    r21:FramedRead<RecvStream,LengthDelimitedCodec>,
    //s21:FramedWrite<SendStream,LengthDelimitedCodec>,
    //r12:FramedRead<RecvStream,LengthDelimitedCodec>,
    }
#[allow(unused_mut)]
impl Comm_Channel {
    pub async fn  send(&mut self,message: Bytes, _which:Choice){
        //0 for alice, 1 for bob
        
            self.s12.send(message).await.unwrap();
        
    }
    pub async fn new(mut source:Client, dest:String,mut des_inc:IncomingStreams)->(Self,Self){
        source.new_channel(dest.clone()).await.unwrap();
        let (mut s12,mut r21) = source.new_direct_stream(dest.clone()).await.unwrap();
        let (_,_, mut s21, mut r12) = des_inc.next().await.unwrap();
        (Comm_Channel{s12,r21:r12},Comm_Channel{s12:s21,r21})
    }
    pub async fn recv(&mut self, _which:Choice) -> Bytes{
        //0 for alice recv
        
            self.r21.try_next().await.unwrap().unwrap().freeze()
        
    }
}
#[allow(non_snake_case)]
pub async fn Start_Judge(cert_path:&Path , key_path:&Path)-> Coord{
    let mut coord_cfg = CoordConfig::new_from_file(cert_path,key_path).unwrap();
    coord_cfg.enable_stateless_retry();
    coord_cfg.set_port(0);// auto assign
    Coord::new(coord_cfg).await.unwrap()

}
#[allow(non_snake_case)]
pub async fn Start_Client(cert_path:&Path ,name: String, port:u16) -> (Client, IncomingStreams){
    let mut client_cfg = ClientConfig::new(name,"localhost".to_string());
        client_cfg.set_ca_from_file(cert_path).unwrap();
        client_cfg.set_port(port);
        Client::new(client_cfg.clone()).await.unwrap()
}
#[allow(unused_mut,non_snake_case)]
pub async fn Send(message: Bytes,mut source:Client, dest:String,mut inc:IncomingStreams)  
{
    //source.new_channel(dest.clone()).await.unwrap();
    let (mut s12,mut r21) = source.new_stream(dest.clone()).await.unwrap();
    let (_,_, mut s21, mut r12) = inc.next().await.unwrap();
    
        s12.send(message.clone()).await.unwrap();
    
    
        
}
#[allow(non_snake_case)]

pub async fn Recv(mut recv: FramedRead<RecvStream,LengthDelimitedCodec>) -> Bytes{
        recv.try_next().await.unwrap().unwrap().freeze()
        
}
/* pub async fn Send(message: Bytes,source:String,dest:String){
    handle.send(message).await.unwrap();

}
pub async fn Recv(mut handle:  FramedRead<RecvStream,LengthDelimitedCodec>) -> Bytes{
    handle.try_next().await.unwrap()
} */