
import dpkt, socket, sys, geoip2.database
from tkinter import *

class pycap():
	def __init__(self, capture, db_path, filter, initialize_window):
		self.capture = capture
		self.db_path = db_path
		self.filter = filter
		self.initialize_window = initialize_window
		self.init_window(capture, db_path, filter)
	
	def init_window(self, capture, db_path, filter):
		global root
		if self.initialize_window == False:
			self.initialize_window = True
			root = Tk()
			root.geometry("1000x500")
			root.title("pycap")
			#root.resizable(width = False, height = False)
			val = StringVar() # value of entry is stored here
			
			status_bar = "NO.          SOURCE                      DESTINATION                      LOCATION (src)                                 LOCATION (dst)                          PROTOCOL"
			status = Label(root, text = status_bar, bd = 1, relief = FLAT, anchor = W)
			status.pack(side = TOP, fill = X)
			
			# /\ search frame /\
			search_frame = Frame(root, relief = FLAT)
			search_frame.pack(side = BOTTOM, fill = X)

			info_txt = ("  {}").format(sys.argv[1])
			info = Label(search_frame, text = info_txt)
			info.pack(side = RIGHT)

			label_entry = Label(search_frame, text = "FILTER:   ")
			label_entry.pack(side = LEFT)

			global filter_entry
			filter_entry = Entry(search_frame, textvariable = val, width = 30)
			filter_entry.pack(side = LEFT)
			filter_entry.bind("<Return>", self.apply_filter)
			
			# /\ search frame /\

			scroll = Scrollbar(root)
			scroll.pack(side = RIGHT, fill = Y)
			
			global listbox
			listbox = Listbox(root, yscrollcommand = scroll.set)
			listbox.bind('<Double-Button>', self.more_info)
			listbox.pack(expand = True, side = "left", fill = "both")
			scroll.config(command = listbox.yview)
		
		else: pass
		f = open(capture)
		pcap = dpkt.pcap.Reader(f)
		for line in self.pcap_reader(pcap, filter): listbox.insert(END, line)
		
		root.mainloop()
	
	def pcap_reader(self, cap, filter):
		global arr
		arr = []
		line = 100
		this_ip = socket.gethostbyname(socket.gethostname())

		for (ts, buf) in cap:
			try:
				eth = dpkt.ethernet.Ethernet(buf)
				ip = eth.data
				src = socket.inet_ntoa(ip.src)
				dst = socket.inet_ntoa(ip.dst)
				protocol = ip.get_proto(ip.p).__name__

				src_copy = src
				dst_copy = dst
				src_lookup = self.ip_lookup(src)
				dst_lookup = self.ip_lookup(dst)
				src_loc_copy = src_lookup
				dst_loc_copy = dst_lookup

				#if src == this_ip: src_lookup = "[YOU]"	
				#elif dst == this_ip: dst_lookup = "[YOU]"

				if(len(src) < 13):
					loops = 13 - len(src)
					for i in range(loops): src += "  "
				
				if(len(dst) < 13):
					loops = 13 - len(dst)
					for i in range(loops): dst += "  "
				
				if(len(src_lookup) < 9):
					loops = 9 - len(src_lookup)
					for i in range(loops): src_lookup += "  "
				
				if(len(dst_lookup) < 9):
					loops = 9 - len(dst_lookup)
					for i in range(loops): dst_lookup += "  "
				data_line = ""
				data_line = ("{}.       {}           {}                         {}                                       {}                                  {}").format(line, src, dst, src_lookup, dst_lookup, protocol)

				if len(filter) == 0:
					line +=1
					arr.append(data_line)
				
				
				else:
					for f in filter:
						fv2 = f.split("=")
						target = fv2[0]
						val = fv2[1]
						if target == "no" and int(val) == line:
							line +=1
							arr.append(data_line)
							break
						elif target == "src" and val == src_copy:
							line +=1
							arr.append(data_line)
							break
						elif target == "dst" and val == dst_copy:
							line +=1
							arr.append(data_line)
							break
						elif target == "src_loc" and val == src_lookup:
							line +=1
							arr.append(data_line)
							break
						elif target == "dst_loc" and val == dst_lookup:
							line +=1
							arr.append(data_line)
							break
						elif target == "proto" and val == protocol:
							line +=1
							arr.append(data_line)
							break


			except: pass
		
		return arr
	
	def apply_filter(self, filter):
		global command
		command = (filter_entry.get()).split(",")
		command_list = ["no","src","dst","src_loc","dst_loc","proto"]

		for filter in command:
			fil = filter.split("=")
			target = fil[0]
			
			if target not in command_list: command.remove(filter)
		
		listbox.delete(0, END)
		self.init_window(self.capture, self.db_path, command)
		
	def ip_lookup(self, ip):
		
		try:
			db = geoip2.database.Reader(self.db_path)
			db_response = db.city(ip)
			country = db_response.country.iso_code
			city = db_response.city.name
			identity = "[" + city + "]"
			db.close()
			return identity

		except: return "[Unknown]"

	def more_info(self, val):
		try:
			selection = listbox.curselection()
			pos = list(selection)[0] + 100
			print(pos)

		except: pass
		
		
		

def main(filter):
	db_path = "/opt/geolite-2/GeoLite2-City.mmdb"
	filter = ""
	try:
		pycap_obj = pycap(sys.argv[1], db_path, filter, False)

	except Exception as err:
		print("[+] {}").format(err)
		sys.exit()

main(filter)
